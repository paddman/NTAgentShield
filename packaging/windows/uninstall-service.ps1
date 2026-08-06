#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$serviceName = "NTAgentShield"

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
}

Write-Host "NTAgentShield service removed. Configuration and evidence under ProgramData were retained intentionally."
