# Optional cleanup only. Run AFTER closing SplitWire and any other application
# that uses WinDivert. This is not required to disable SplitWire filtering.
$ErrorActionPreference = 'Continue'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this script from an elevated PowerShell.'
    exit 1
}
Write-Host 'Stopping WinDivert driver service (if present)...'
& sc.exe stop WinDivert | Out-Host
Write-Host 'Deleting WinDivert driver service registration (if present)...'
& sc.exe delete WinDivert | Out-Host
Write-Host 'Done. If Windows reports the service is marked for deletion, reboot once.'
