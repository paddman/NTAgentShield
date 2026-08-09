#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\NTAgentShield",
    [string]$DataDir = "$env:ProgramData\NTAgentShield",
    [switch]$RemoveFiles,
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$taskName = "NTAgentShield"

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$service = Get-CimInstance Win32_Service -Filter "Name='NTAgentShield'" -ErrorAction SilentlyContinue
if ($service) {
    if ($service.PathName -notmatch "(?i)NTAgentShield|ntagentshield-agent") {
        throw "Refusing to remove a different service named NTAgentShield."
    }
    Stop-Service -Name $taskName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $taskName | Out-Null
}

if ($RemoveFiles -and (Test-Path -LiteralPath $InstallDir)) {
    $appPath = Join-Path $InstallDir "NTAgentShield.App.exe"
    $appProcess = Get-Process -Name "NTAgentShield.App" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $appPath }
    if ($appProcess) { $appProcess | Stop-Process -Force }
    Remove-Item -LiteralPath (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NTAgentShield.lnk") -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}
if ($RemoveData -and (Test-Path -LiteralPath $DataDir)) {
    Remove-Item -LiteralPath $DataDir -Recurse -Force
}

Write-Host "NTAgentShield task removed. Configuration and evidence were retained unless -RemoveData was supplied."
