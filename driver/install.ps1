# Pek.ROutGuard 文件过滤驱动 —— 安装（开发/测试用）
#
# 做四件事：
#   1. 检查测试签名模式（未开则提示并给出命令，**不自动重启**）
#   2. 注册内核服务 + minifilter 高度（避开本机已有加密驱动）
#   3. fltmc 加载
#   4. 校验加载结果（fltmc filters / fltmc instances）
#
# 用法：
#   .\install.ps1              # 安装并加载
#   .\install.ps1 -NoLoad      # 只注册，不加载

[CmdletBinding()]
param(
    [switch]$NoLoad,
    [string]$Altitude = '404900'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$sys = Join-Path $root 'build\PekOutGuardFilter.sys'
$serviceName = 'PekOutGuardFilter'
$instanceName = 'PekOutGuard Instance'

if (-not (Test-Path $sys)) {
    throw "找不到驱动文件：$sys（先运行 .\build.ps1）"
}

# ————— 1. 检查测试签名 —————
$bcd = (bcdedit /enum '{current}' 2>&1 | Out-String)
if ($bcd -notmatch 'testsigning\s+Yes') {
    Write-Host '[install] 当前**未开启**测试签名模式，驱动无法加载。' -ForegroundColor Yellow
    Write-Host '          请以管理员身份执行下面命令，然后**重启一次**，再重新运行本脚本：' -ForegroundColor Yellow
    Write-Host '              bcdedit /set testsigning on' -ForegroundColor Cyan
    Write-Host '          （生产环境改为 EV 证书 + 微软 attestation 签名，不需要 testsigning）' -ForegroundColor DarkGray
    if (-not $NoLoad) { throw '测试签名未开启，已中止' }
}

# ————— 2. 检查高度冲突 —————
Write-Host '[install] 当前已加载的过滤驱动：'
$existing = & cmd.exe /c 'fltmc filters 2>nul'
$existing | Select-Object -First 12 | ForEach-Object { "          $_" }
foreach ($line in ($existing -split "`r?`n")) {
    if ($line -match '^\s*(\S+)\s+(\d+)\s+(\d+)') {
        $name = $Matches[1]; $alt = [int]$Matches[3]
        if ($alt -eq [int]$Altitude) {
            throw "高度冲突：已有的 $name 占用了 $Altitude，请用 -Altitude 换一个（加密区间 400000~409999）"
        }
    }
}

# ————— 3. 注册服务 —————
Write-Host "[install] 注册服务 $serviceName ..."
$existingSvc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Host '[install] 已存在同名服务，先删除'
    & cmd.exe /c "sc.exe stop $serviceName >nul 2>&1"
    & cmd.exe /c "fltmc unload $serviceName >nul 2>&1"
    & cmd.exe /c "sc.exe delete $serviceName >nul 2>&1"
    Start-Sleep -Milliseconds 500
}
# 注意：sc.exe 在 PowerShell 里做引号嵌套极易触发 1639(INVALID_COMMAND_LINE)，
# 而内核服务项本质就是注册表，直接写更可控、可重复。
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
if (Test-Path $svcKey) { Remove-Item $svcKey -Recurse -Force }
New-Item -Path $svcKey -Force | Out-Null
Set-ItemProperty -Path $svcKey -Name 'Type'      -Value 2                        -Type DWord          # SERVICE_FILE_SYSTEM_DRIVER
Set-ItemProperty -Path $svcKey -Name 'Start'     -Value 3                        -Type DWord          # DEMAND_START
Set-ItemProperty -Path $svcKey -Name 'ErrorControl' -Value 1                     -Type DWord
Set-ItemProperty -Path $svcKey -Name 'ImagePath' -Value "\??\$sys"               -Type ExpandString
Set-ItemProperty -Path $svcKey -Name 'DisplayName' -Value 'Pek.ROutGuard Filter' -Type String
Write-Host "[install] 服务项已写入：$svcKey"

$instKey = Join-Path $svcKey 'Instances'
New-Item -Path $instKey -Force | Out-Null
New-Item -Path (Join-Path $instKey $instanceName) -Force | Out-Null
Set-ItemProperty -Path $instKey -Name '(Default)' -Value $instanceName
Set-ItemProperty -Path (Join-Path $instKey $instanceName) -Name 'Altitude' -Value $Altitude -Type String
Set-ItemProperty -Path (Join-Path $instKey $instanceName) -Name 'Flags'    -Value 0         -Type DWord
Write-Host "[install] 高度已设为 $Altitude"

if ($NoLoad) {
    Write-Host '[install] 已按 -NoLoad 跳过加载。加载命令：fltmc load PekOutGuardFilter' -ForegroundColor Green
    exit 0
}

# ————— 4. 加载并验证 —————
Write-Host '[install] 加载驱动 ...'
& cmd.exe /c "fltmc load $serviceName"
if ($LASTEXITCODE -ne 0) {
    throw "fltmc load 失败（退出码 $LASTEXITCODE）。常见原因：签名无效（需 testsigning）、高度冲突"
}

Start-Sleep -Milliseconds 800
$filters = & cmd.exe /c 'fltmc filters 2>nul'
if ($filters -match $serviceName) {
    Write-Host "[install] 加载成功：" -ForegroundColor Green
    ($filters -split "`r?`n" | Select-Object -First 1) | ForEach-Object { "          $_" }
    ($filters -split "`r?`n" | Where-Object { $_ -match $serviceName }) | ForEach-Object { "          $_" }
} else {
    throw '加载后未在 fltmc filters 中看到该驱动'
}

Write-Host ''
Write-Host '[install] 下一步：用用户态工具读取统计（IOCTL 已开放）' -ForegroundColor Cyan
Write-Host '          OUG_IOCTL_GET_STATS / SET_ENABLED / GET_VERSION'
Write-Host '          设备名：\\.\PekOutGuardFilter'
