#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\NTAgentShield",
    [string]$DataDir = "$env:ProgramData\NTAgentShield",
    [switch]$RemoveFiles,
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$ServiceName = "NTAgentShield"

$legacyTask = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
if ($legacyTask) {
    Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
}

$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if ($service) {
    if ($service.PathName -notmatch "(?i)NTAgentShield|ntagentshield-agent") {
        throw "Refusing to remove a different service named $ServiceName."
    }
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to delete $ServiceName service." }
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

Write-Host "NTAgentShield Windows Service removed. Configuration and evidence were retained unless -RemoveData was supplied."
