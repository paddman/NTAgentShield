#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$PackageDir = "",
    [string]$InstallDir = "$env:ProgramFiles\NTAgentShield",
    [string]$DataDir = "$env:ProgramData\NTAgentShield",
    [switch]$ForceConfig
)

$ErrorActionPreference = "Stop"
if (-not $PackageDir) { $PackageDir = Join-Path $PSScriptRoot "..\..\dist\windows\package" }
Write-Warning "install-service.ps1 is retained as a compatibility alias. NTAgentShield is installed as a SYSTEM Scheduled Task because the Go binary is not an SCM-native service executable."
& (Join-Path $PSScriptRoot "install.ps1") -PackageDir $PackageDir -InstallDir $InstallDir -DataDir $DataDir -ForceConfig:$ForceConfig
