#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$PackageDir = "",
    [string]$InstallDir = "$env:ProgramFiles\NTAgentShield",
    [string]$DataDir = "$env:ProgramData\NTAgentShield",
    [switch]$ForceConfig
)

$ErrorActionPreference = "Stop"
$TaskName = "NTAgentShield"
if (-not $PackageDir) { $PackageDir = $PSScriptRoot }
$PackageDir = (Resolve-Path -LiteralPath $PackageDir).Path
$AgentSource = Join-Path $PackageDir "ntagentshield-agent-windows-amd64.exe"
$CtlSource = Join-Path $PackageDir "ntagentshieldctl-windows-amd64.exe"
$InventorySource = Join-Path $PackageDir "ntagentshield-inventory-windows-amd64.exe"
$EnrollSource = Join-Path $PackageDir "ntagentshield-enroll-windows-amd64.exe"
$ConfigSource = Join-Path $PackageDir "config\windows.example.json"
$PolicySource = Join-Path $PackageDir "policies\default-policy.json"

foreach ($required in @($AgentSource, $ConfigSource, $PolicySource)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Package file is missing: $required"
    }
}

$service = Get-CimInstance Win32_Service -Filter "Name='NTAgentShield'" -ErrorAction SilentlyContinue
if ($service) {
    $ownedService = $service.PathName -match "(?i)NTAgentShield|ntagentshield-agent"
    if (-not $ownedService) { throw "A different service already uses the name NTAgentShield." }
    Stop-Service -Name $TaskName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $TaskName | Out-Null
    Start-Sleep -Seconds 2
}

$oldTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($oldTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false

    $oldAgentPath = Join-Path $InstallDir "ntagentshield-agent.exe"
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $oldProcess = Get-Process -Name "ntagentshield-agent" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $oldAgentPath }
        if ($oldProcess) { Start-Sleep -Seconds 1 }
    } while ($oldProcess -and (Get-Date) -lt $deadline)
    if ($oldProcess) {
        $oldProcess | Stop-Process -Force
        Start-Sleep -Seconds 2
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, (Join-Path $InstallDir "policies") | Out-Null
Copy-Item -LiteralPath $AgentSource -Destination (Join-Path $InstallDir "ntagentshield-agent.exe") -Force
foreach ($optional in @(
    @{ Source = $CtlSource; Name = "ntagentshieldctl.exe" },
    @{ Source = $InventorySource; Name = "ntagentshield-inventory.exe" },
    @{ Source = $EnrollSource; Name = "ntagentshield-enroll.exe" }
)) {
    if (Test-Path -LiteralPath $optional.Source -PathType Leaf) {
        Copy-Item -LiteralPath $optional.Source -Destination (Join-Path $InstallDir $optional.Name) -Force
    }
}

$policyTarget = Join-Path $InstallDir "policies\default-policy.json"
if (-not (Test-Path -LiteralPath $policyTarget)) {
    Copy-Item -LiteralPath $PolicySource -Destination $policyTarget -Force
}
$configTarget = Join-Path $DataDir "agent.json"
if ($ForceConfig -or -not (Test-Path -LiteralPath $configTarget)) {
    Copy-Item -LiteralPath $ConfigSource -Destination $configTarget -Force
}

# Keep config, enrollment material, API token, and evidence private to SYSTEM and Administrators.
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to secure data directory ACLs: $DataDir" }

$agentPath = Join-Path $InstallDir "ntagentshield-agent.exe"
$argument = '--config "{0}"' -f $configTarget
$action = New-ScheduledTaskAction -Execute $agentPath -Argument $argument -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "NTAgentShield endpoint security agent." | Out-Null
Start-ScheduledTask -TaskName $TaskName

$deadline = (Get-Date).AddSeconds(30)
do {
    Start-Sleep -Seconds 1
    $running = Get-Process -Name "ntagentshield-agent" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $agentPath }
} while (-not $running -and (Get-Date) -lt $deadline)

if (-not $running) {
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    throw "NTAgentShield did not start. LastTaskResult=$($info.LastTaskResult)"
}

Write-Host "NTAgentShield installed and running."
Write-Host "Task       : $TaskName (SYSTEM, at startup)"
Write-Host "Binary     : $agentPath"
Write-Host "Config     : $configTarget"
Write-Host "Data       : $DataDir"
