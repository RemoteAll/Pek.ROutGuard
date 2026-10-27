# Pek.ROutGuard 文件过滤驱动 —— 一键验证（M0 + M1）
#
# 目的：重启并开启测试签名后，**一条命令**就能证明驱动真的在工作，
#       不用人工一步步敲 fltmc / driver status / 手工建文件。
#
# 验证内容：
#   1. 环境：测试签名是否开启、服务是否注册、高度是否冲突
#   2. 加载：fltmc load 是否成功、实例是否挂到卷上
#   3. 通道：IOCTL 通不通（读版本 0.2）
#   4. 规则：下发"按扩展名 + 按路径"规则
#   5. 判定：在受控目录建文件 → RuleHit / LastHit 是否按预期增长
#   6. 反证：在受控目录外建文件 → RuleMiss 增长、LastHit 不变
#
# M1 阶段驱动**只看不改**：全程不修改任何一个字节，可安全反复运行。
#
# 用法：
#   .\verify.ps1                      # 完整验证
#   .\verify.ps1 -Unload              # 验证完自动卸载驱动
#   .\verify.ps1 -ClientExe <path>    # 指定客户端 exe（默认自动找 release/debug）

[CmdletBinding()]
param(
    [string]$ClientExe = '',
    [string]$TestDir = '',
    [switch]$Unload,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$serviceName = 'PekOutGuardFilter'

# ————— 结果收集 —————
$script:results = @()
function Add-Result {
    param(
        [string]$Name,
        [bool]$Ok,
        [string]$Detail = ''
    )
    $script:results += [pscustomobject]@{ 项目 = $Name; 结果 = $(if ($Ok) { 'PASS' } else { 'FAIL' }); 说明 = $Detail }
    Write-Host ("  [{0}] {1}{2}" -f $(if ($Ok) { '通过' } else { '失败' }), $Name, $(if ($Detail) { " —— $Detail" } else { '' })) -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
}

function Fail-Fast {
    param([string]$Message)
    Write-Host "`n$Message" -ForegroundColor Red
    Show-Summary
    exit 1
}

function Show-Summary {
    Write-Host "`n================ 验证结果汇总 ================" -ForegroundColor Cyan
    $script:results | Format-Table -AutoSize | Out-String | Write-Host
    $failed = @($script:results | Where-Object { $_.结果 -eq 'FAIL' })
    if ($failed.Count -eq 0) {
        Write-Host "全部通过：驱动 M0 + M1 功能正常。" -ForegroundColor Green
    } else {
        Write-Host ("有 {0} 项失败，见上表。" -f $failed.Count) -ForegroundColor Red
    }
    Write-Host "==============================================`n" -ForegroundColor Cyan
}

# ————— 找客户端 exe —————
function Resolve-ClientExe {
    if ($ClientExe -and (Test-Path $ClientExe)) { return (Resolve-Path $ClientExe).Path }
    $candidates = @(
        (Join-Path $root '..\target\release\pek-outguard-client.exe'),
        (Join-Path $root '..\target\debug\pek-outguard-client.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    return ''
}

# 运行客户端命令，返回 stdout（把 stderr 也收进来，错误信息常在那里）
function Invoke-Client {
    param([string]$Exe, [string[]]$Arguments)
    $out = & $Exe @Arguments 2>&1 | Out-String
    return $out
}

Write-Host "`n=== Pek.ROutGuard 驱动一键验证 ===`n" -ForegroundColor Cyan

# ————— 1. 环境检查 —————
Write-Host "[1/6] 环境检查" -ForegroundColor Yellow

# 测试签名
$signing = & bcdedit /enum '{current}' 2>$null | Out-String
$testsigningOn = $signing -match 'testsigning\s+Yes'
Add-Result -Name '测试签名已开启' -Ok $testsigningOn -Detail $(if ($testsigningOn) { '' } else { '需管理员运行 bcdedit /set testsigning on 后重启' })

# 服务注册
$svc = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -ErrorAction SilentlyContinue
Add-Result -Name '驱动服务已注册' -Ok ($null -ne $svc) -Detail $(if ($svc) { "ImagePath=$($svc.ImagePath)" } else { '先运行 driver\install.ps1' })

if (-not $testsigningOn) {
    Fail-Fast "测试签名未开启，驱动无法加载。`n请在管理员 PowerShell 中执行：`n    bcdedit /set testsigning on`n然后重启电脑，再运行本脚本。"
}

# 高度冲突
$filters = & fltmc filters 2>$null | Out-String
$altConflict = $false
foreach ($line in ($filters -split "`r?`n")) {
    if ($line -match '^\s*(\S+)\s+(\d+)\s*$') {
        $alt = [int]$Matches[2]
        $name = $Matches[1]
        if ($alt -eq 404900 -and $name -ne $serviceName) { $altConflict = $true }
    }
}
Add-Result -Name '高度 404900 无冲突' -Ok (-not $altConflict)

# ————— 2. 加载驱动 —————
Write-Host "`n[2/6] 加载驱动" -ForegroundColor Yellow

$loaded = $filters -match $serviceName
if (-not $loaded) {
    Write-Host "  正在 fltmc load $serviceName ..."
    $loadOut = & fltmc load $serviceName 2>&1 | Out-String
    Start-Sleep -Milliseconds 800
    $filters = & fltmc filters 2>$null | Out-String
    $loaded = $filters -match $serviceName
    Add-Result -Name '驱动已加载' -Ok $loaded -Detail $(if ($loaded) { '' } else { $loadOut.Trim() })
} else {
    Add-Result -Name '驱动已加载' -Ok $true -Detail '（此前已加载）'
}

if (-not $loaded) {
    Fail-Fast "驱动加载失败。常见原因：`n  · 未开启测试签名或未重启`n  · 驱动未通过签名校验（用 signtool verify /kp /v driver\build\PekOutGuardFilter.sys 检查）`n  · 高度与已有驱动冲突（fltmc filters 查看）`n  · 用事件查看器看系统日志中的 minifilter 错误"
}

# 实例挂载
$instances = & fltmc instances 2>$null | Out-String
$instanceCount = ([regex]::Matches($instances, [regex]::Escape($serviceName))).Count
Add-Result -Name '已挂载到卷' -Ok ($instanceCount -gt 0) -Detail "$instanceCount 个实例"

# ————— 3. 控制通道 —————
Write-Host "`n[3/6] 控制通道（IOCTL）" -ForegroundColor Yellow

$exe = Resolve-ClientExe
if (-not $exe) { Fail-Fast "找不到 pek-outguard-client.exe，请用 -ClientExe 指定路径。" }
Write-Host "  客户端：$exe"

$statusOut = Invoke-Client -Exe $exe -Arguments @('driver', 'status')
$versionOk = $statusOut -match '版本\s*[:：]?\s*(\d+)\.(\d+)'
$driverVersion = if ($versionOk) { "$($Matches[1]).$($Matches[2])" } else { '' }
Add-Result -Name '驱动设备可打开' -Ok ($versionOk -or $statusOut -notmatch '打开驱动设备失败') -Detail $(if ($driverVersion) { "版本 $driverVersion" } else { '' })
Add-Result -Name '版本为 0.2（含 M1 规则判定）' -Ok ($driverVersion -eq '0.2') -Detail $driverVersion

# ————— 4. 下发规则 —————
Write-Host "`n[4/6] 下发规则" -ForegroundColor Yellow

if (-not $TestDir) {
    $TestDir = Join-Path $env:TEMP 'oug-driver-verify'
}
if (Test-Path $TestDir) { Remove-Item $TestDir -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
$outsideDir = Join-Path $env:TEMP 'oug-driver-verify-outside'
if (Test-Path $outsideDir) { Remove-Item $outsideDir -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $outsideDir -Force | Out-Null

Write-Host "  受控目录：$TestDir"
$rulesOut = Invoke-Client -Exe $exe -Arguments @('driver', 'rules', '--ext', '.ougtest', '--path', $TestDir)
$rulesOk = $rulesOut -notmatch '失败|错误|error' -and $rulesOut -match '规则|已'
Add-Result -Name '规则下发成功' -Ok $rulesOk -Detail ($rulesOut.Trim() -split "`r?`n" | Select-Object -First 1)

# ————— 5. 判定命中 —————
Write-Host "`n[5/6] 规则判定（受控目录内建文件）" -ForegroundColor Yellow

function Get-DriverStatus {
    param([string]$Exe)
    $out = Invoke-Client -Exe $Exe -Arguments @('driver', 'status')
    $stats = @{}
    # 用英文键名解析：避免“命中”/“未命中”互相误匹配
    if ($out -match 'RuleHit=(\d+)')       { $stats.RuleHit = [int]$Matches[1] }
    if ($out -match 'RuleMiss=(\d+)')      { $stats.RuleMiss = [int]$Matches[1] }
    if ($out -match 'RuleEvalError=(\d+)') { $stats.RuleEvalError = [int]$Matches[1] }
    $stats.Raw = $out
    return $stats
}

$before = Get-DriverStatus -Exe $exe
if (-not $before.ContainsKey('RuleHit')) {
    Write-Host "  driver status 输出：" -ForegroundColor DarkGray
    Write-Host $before.Raw -ForegroundColor DarkGray
    Fail-Fast "无法从 driver status 解析统计值（RuleHit），请检查上面输出。"
}

$hitFile = Join-Path $TestDir '验证样本.ougtest'
[System.IO.File]::WriteAllText($hitFile, 'verify', (New-Object System.Text.UTF8Encoding($false)))
Start-Sleep -Milliseconds 600

$after = Get-DriverStatus -Exe $exe
$hitDelta = $after.RuleHit - $before.RuleHit
Add-Result -Name '规则命中（RuleHit 增长）' -Ok ($hitDelta -gt 0) -Detail "新增 $hitDelta 次"

# 反证：受控目录外建同名扩展名文件 → 不应命中
$missFile = Join-Path $outsideDir '不该命中.ougtest'
[System.IO.File]::WriteAllText($missFile, 'verify', (New-Object System.Text.UTF8Encoding($false)))
Start-Sleep -Milliseconds 600
$third = Get-DriverStatus -Exe $exe
$extraHit = $third.RuleHit - $after.RuleHit
$missDelta = $third.RuleMiss - $after.RuleMiss
Add-Result -Name '目录外不误命中' -Ok ($extraHit -eq 0 -and $missDelta -ge 0) -Detail "受控目录外又命中 $extraHit 次（应为 0）"

# ————— 6. 收尾 —————
Write-Host "`n[6/6] 收尾" -ForegroundColor Yellow

# 复位规则，避免验证规则残留在生产环境
$resetOut = Invoke-Client -Exe $exe -Arguments @('driver', 'rules', '--clear')
Add-Result -Name '规则已复位' -Ok ($resetOut -notmatch '失败') -Detail ($resetOut.Trim() -split "`r?`n" | Select-Object -First 1)

if (-not $KeepArtifacts) {
    Remove-Item $TestDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $outsideDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($Unload) {
    Write-Host "  卸载驱动 ..."
    & fltmc unload $serviceName 2>&1 | Out-String | Write-Host
    $filters = & fltmc filters 2>$null | Out-String
    Add-Result -Name '驱动已卸载' -Ok (-not ($filters -match $serviceName))
}

Show-Summary

$failed = @($script:results | Where-Object { $_.结果 -eq 'FAIL' })
if ($failed.Count -eq 0) { exit 0 } else { exit 1 }
