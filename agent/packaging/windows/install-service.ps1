#requires -RunAsAdministrator
param(
    [string]$BinaryPath = "$PSScriptRoot\..\..\dist\ntagentshield-agent-windows-amd64.exe",
    [string]$InstallDir = "$env:ProgramFiles\NTAgentShield",
    [string]$ConfigPath = "$env:ProgramData\NTAgentShield\agent.json"
)

$ErrorActionPreference = "Stop"
$serviceName = "NTAgentShield"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $ConfigPath) | Out-Null
Copy-Item -Force $BinaryPath "$InstallDir\ntagentshield-agent.exe"

if (-not (Test-Path $ConfigPath)) {
    Copy-Item "$PSScriptRoot\..\..\config\windows.example.json" $ConfigPath
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}

$command = '"{0}" --config "{1}"' -f "$InstallDir\ntagentshield-agent.exe", $ConfigPath
sc.exe create $serviceName binPath= $command start= auto DisplayName= "NTAgentShield Security Agent" | Out-Null
sc.exe description $serviceName "AI-assisted endpoint/server security agent with deterministic policy boundaries." | Out-Null
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/""/0 | Out-Null
Start-Service -Name $serviceName
Get-Service -Name $serviceName
