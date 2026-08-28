#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$PackageDir = "",
    [string]$InstallDir = "$env:ProgramFiles\NTAgentShield",
    [string]$DataDir = "$env:ProgramData\NTAgentShield",
    [string]$UpdatePublicKeyPath = "",
    [switch]$ForceConfig
)

$ErrorActionPreference = "Stop"
$ServiceName = "NTAgentShield"
if (-not $PackageDir) { $PackageDir = $PSScriptRoot }
$PackageDir = (Resolve-Path -LiteralPath $PackageDir).Path
$AgentSource = Join-Path $PackageDir "ntagentshield-agent-windows-amd64.exe"
$CtlSource = Join-Path $PackageDir "ntagentshieldctl-windows-amd64.exe"
$InventorySource = Join-Path $PackageDir "ntagentshield-inventory-windows-amd64.exe"
$EnrollSource = Join-Path $PackageDir "ntagentshield-enroll-windows-amd64.exe"
$UpdaterSource = Join-Path $PackageDir "ntagentshield-updater-windows-amd64.exe"
$ConfigSource = Join-Path $PackageDir "config\windows.example.json"
$PolicySource = Join-Path $PackageDir "policies\default-policy.json"
$AppSource = Join-Path $PackageDir "NTAgentShield.App.exe"

foreach ($required in @($AgentSource, $ConfigSource, $PolicySource)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Package file is missing: $required"
    }
}

$existing = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.PathName -notmatch "(?i)NTAgentShield|ntagentshield-agent") {
        throw "A different service already uses the name $ServiceName."
    }
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 500
        $existing = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    } while ($existing -and (Get-Date) -lt $deadline)
    if ($existing) { throw "Timed out deleting the previous $ServiceName service." }
}

$legacyTask = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
if ($legacyTask) {
    Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, (Join-Path $InstallDir "policies") | Out-Null
$appTarget = Join-Path $InstallDir "NTAgentShield.App.exe"
$appProcess = Get-Process -Name "NTAgentShield.App" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $appTarget }
if ($appProcess) {
    $appProcess | Stop-Process -Force
    Start-Sleep -Seconds 1
}

$copyMap = @(
    @{ Source = $AgentSource; Name = "ntagentshield-agent.exe" },
    @{ Source = $CtlSource; Name = "ntagentshieldctl.exe" },
    @{ Source = $InventorySource; Name = "ntagentshield-inventory.exe" },
    @{ Source = $EnrollSource; Name = "ntagentshield-enroll.exe" },
    @{ Source = $UpdaterSource; Name = "ntagentshield-updater.exe" }
)
foreach ($item in $copyMap) {
    if (Test-Path -LiteralPath $item.Source -PathType Leaf) {
        Copy-Item -LiteralPath $item.Source -Destination (Join-Path $InstallDir $item.Name) -Force
    }
}
if (Test-Path -LiteralPath $AppSource -PathType Leaf) {
    Copy-Item -LiteralPath $AppSource -Destination $appTarget -Force
    $startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    New-Item -ItemType Directory -Force -Path $startMenu | Out-Null
    $shortcutPath = Join-Path $startMenu "NTAgentShield.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $appTarget
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.IconLocation = "$appTarget,0"
    $shortcut.Description = "NTAgentShield Windows dashboard"
    $shortcut.Save()
}

$policyTarget = Join-Path $InstallDir "policies\default-policy.json"
if (-not (Test-Path -LiteralPath $policyTarget)) {
    Copy-Item -LiteralPath $PolicySource -Destination $policyTarget -Force
}
$configTarget = Join-Path $DataDir "agent.json"
if ($ForceConfig -or -not (Test-Path -LiteralPath $configTarget)) {
    Copy-Item -LiteralPath $ConfigSource -Destination $configTarget -Force
}
if ($UpdatePublicKeyPath) {
    $resolvedKey = (Resolve-Path -LiteralPath $UpdatePublicKeyPath).Path
    Copy-Item -LiteralPath $resolvedKey -Destination (Join-Path $DataDir "update-signing.pub") -Force
}

# Program files are immutable to standard users. Agent state is private to SYSTEM and Administrators.
& icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to secure installation directory ACLs: $InstallDir" }
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to secure data directory ACLs: $DataDir" }

$agentPath = Join-Path $InstallDir "ntagentshield-agent.exe"
$binaryPath = '"{0}" --config "{1}"' -f $agentPath, $configTarget
New-Service -Name $ServiceName -BinaryPathName $binaryPath -DisplayName "NTAgentShield Endpoint Agent" -StartupType Automatic | Out-Null
& sc.exe description $ServiceName "Signed NTAgentShield endpoint detection and response service." | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to configure Windows Service description." }
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to configure Windows Service recovery." }
& sc.exe failureflag $ServiceName 1 | Out-Null
& sc.exe sidtype $ServiceName unrestricted | Out-Null
& sc.exe config $ServiceName start= delayed-auto | Out-Null
Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

Write-Host "NTAgentShield installed and running."
Write-Host "Service    : $ServiceName (Windows SCM, LocalSystem, delayed automatic)"
Write-Host "Binary     : $agentPath"
Write-Host "Config     : $configTarget"
Write-Host "Data       : $DataDir"
if (Test-Path -LiteralPath (Join-Path $InstallDir "ntagentshield-updater.exe")) {
    Write-Host "Updater    : $(Join-Path $InstallDir 'ntagentshield-updater.exe')"
}
if (-not (Test-Path -LiteralPath (Join-Path $DataDir "update-signing.pub"))) {
    Write-Warning "Signed updater is installed but disabled until an Ed25519 public key is provisioned."
}
if (Test-Path -LiteralPath $appTarget) { Write-Host "App        : $appTarget (Start Menu shortcut created)" }
