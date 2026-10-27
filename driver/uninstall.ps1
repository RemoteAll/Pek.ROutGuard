# Pek.ROutGuard 文件过滤驱动 —— 卸载（开发/测试用）
#
# 顺序很重要：先 fltmc unload（让驱动自己收尾），再删服务，最后清注册表。
# 如果卸载时 BSOD，说明驱动有 bug——查看 C:\Windows\MEMORY.DMP 或 Minidump。

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$serviceName = 'PekOutGuardFilter'

Write-Host "[uninstall] 卸载过滤驱动 $serviceName ..."
& fltmc unload $serviceName 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host '[uninstall] fltmc unload 失败（可能本来就未加载），继续清理' -ForegroundColor Yellow
} else {
    Write-Host '[uninstall] 已卸载' -ForegroundColor Green
}

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host '[uninstall] 服务已删除' -ForegroundColor Green }
    else { Write-Host '[uninstall] 服务删除失败（可能被占用，重启后自动消失）' -ForegroundColor Yellow }
} else {
    Write-Host '[uninstall] 服务本就不存在'
}

$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
if (Test-Path $svcKey) {
    Remove-Item $svcKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host '[uninstall] 注册表项已清理'
}

Write-Host ''
Write-Host '[uninstall] 完成。若之后不再做驱动开发，建议关闭测试签名：' -ForegroundColor Cyan
Write-Host '              bcdedit /set testsigning off' -ForegroundColor Cyan
Write-Host '            （关闭后需重启；开发用证书 CN=PekOutGuard Dev Test 可自行从证书管理器删除）'
