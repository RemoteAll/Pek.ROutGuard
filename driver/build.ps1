# Pek.ROutGuard 文件过滤驱动构建脚本
#
# 为什么不用 vcxproj：本机是 VS 2026 (v18)，而 WDK 10.0.26100 的 VS 集成只支持到 VS2022，
# 没有 WindowsKernelModeDriver toolset。这里直接用 cl.exe + link.exe 命令行编译，
# 依赖最少、可重复、在 CI 里也能跑。
#
# 用法：
#   .\build.ps1                # 编译 Release x64
#   .\build.ps1 -Clean         # 先清理

[CmdletBinding()]
param(
    [switch]$Clean,
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = Join-Path $root 'build'

# ————— 定位工具链 —————
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "找不到 vswhere：$vswhere（需要安装 Visual Studio）" }

$vsPath = $null
# 先按正式版找；找不到再放开 prerelease（本机是 VS 2026 Insiders）
foreach ($extra in @(@(), @('-prerelease'))) {
    $args = @('-latest', '-products', '*') + $extra + @('-property', 'installationPath')
    $candidate = (& $vswhere @args 2>$null | Select-Object -First 1)
    if ($candidate -and (Test-Path $candidate.Trim())) {
        $vsPath = $candidate.Trim()
        break
    }
}
if (-not $vsPath) { throw '找不到 Visual Studio 安装路径（vswhere 未返回任何实例）' }

$msvcRoot = Join-Path $vsPath 'VC\Tools\MSVC'
if (-not (Test-Path $msvcRoot)) { throw "找不到 MSVC 工具链：$msvcRoot" }
$msvc = Get-ChildItem $msvcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
$msvcPath = $msvc.FullName

$cl = Join-Path $msvcPath 'bin\Hostx64\x64\cl.exe'
if (-not (Test-Path $cl)) { throw "找不到 cl.exe：$cl" }

# ————— 定位 WDK —————
$kitsRoot = 'C:\Program Files (x86)\Windows Kits\10'
$wdkVersion = Get-ChildItem (Join-Path $kitsRoot 'Include') -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'km\fltKernel.h') } |
    Sort-Object Name -Descending |
    Select-Object -First 1
if (-not $wdkVersion) {
    throw '找不到 WDK 头文件（需要 Windows Driver Kit，且需含 km\fltKernel.h）'
}
$wdkVer = $wdkVersion.Name
Write-Host "[build] VS        : $vsPath"
Write-Host "[build] MSVC      : $($msvc.Name)"
Write-Host "[build] WDK/SDK   : $wdkVer"

$incKm     = Join-Path $kitsRoot "Include\$wdkVer\km"
$incShared = Join-Path $kitsRoot "Include\$wdkVer\shared"
# 注意：**不要**加 ucrt——它和内核的 locale_t 会冲突（error C2371）。
# 内核模式用的是 km\crt 里的精简 CRT。
$incKmCrt  = Join-Path $kitsRoot "Include\$wdkVer\km\crt"
$libKm     = Join-Path $kitsRoot "Lib\$wdkVer\km\x64"
$libKmCrt  = Join-Path $kitsRoot "Lib\$wdkVer\km\x64\crt"

foreach ($p in @($incKm, $incShared, $incKmCrt, $libKm)) {
    if (-not (Test-Path $p)) { throw "工具链路径缺失：$p" }
}

# ————— 准备输出目录 —————
if ($Clean -and (Test-Path $outDir)) { Remove-Item $outDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$src = Join-Path $root 'src\main.c'
$obj = Join-Path $outDir 'main.obj'
$sys = Join-Path $outDir 'PekOutGuardFilter.sys'

$includeArgs = @(
    "/I`"$incKm`"",
    "/I`"$incShared`"",
    "/I`"$incKmCrt`"",
    "/I`"$msvcPath\include`""
)

$optFlags = if ($Configuration -eq 'Debug') { @('/Od', '/Zi') } else { @('/O2') }

Write-Host "[build] 编译 main.c ..."
$compileArgs = @(
    '/nologo', '/c', '/W4', '/WX-', '/GS-', '/kernel',
    '/D_KERNEL_MODE', '/DPOOL_NX_OPTIN=1',
    '/D_AMD64_', '/DAMD64',
    '/DUNICODE', '/D_UNICODE',
    '/DNDEBUG'
) + $optFlags + $includeArgs + @("/Fo`"$obj`"", "`"$src`"")

& $cl @compileArgs
if ($LASTEXITCODE -ne 0) { throw "编译失败（cl.exe 退出码 $LASTEXITCODE）" }

Write-Host "[build] 链接 $sys ..."
$linkArgs = @(
    '/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE', '/ENTRY:DriverEntry',
    '/NODEFAULTLIB', '/RELEASE',
    "/LIBPATH:`"$libKm`"",
    "/LIBPATH:`"$libKmCrt`"",
    "/LIBPATH:`"$msvcPath\lib\x64`"",
    "/OUT:`"$sys`"",
    "`"$obj`"",
    'ntoskrnl.lib', 'fltMgr.lib'
)
& "$msvcPath\bin\Hostx64\x64\link.exe" @linkArgs
if ($LASTEXITCODE -ne 0) { throw "链接失败（link.exe 退出码 $LASTEXITCODE）" }

$file = Get-Item $sys
Write-Host ""
Write-Host ("[build] 完成：{0}（{1:N0} 字节）" -f $file.FullName, $file.Length) -ForegroundColor Green
Write-Host "[build] 注意：加载前需要开启测试签名（bcdedit /set testsigning on）并重启，见 docs/minifilter透明加密设计.md"
