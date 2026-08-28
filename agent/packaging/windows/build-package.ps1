[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$OutputDir = "dist\windows"
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RepoRoot = (Resolve-Path (Join-Path $Root "..")).Path
$OutputPath = if ([IO.Path]::IsPathRooted($OutputDir)) {
    [IO.Path]::GetFullPath($OutputDir)
} else {
    [IO.Path]::GetFullPath((Join-Path $Root $OutputDir))
}

$Go = (Get-Command go.exe -ErrorAction SilentlyContinue).Source
if (-not $Go) {
    $candidate = Join-Path $env:ProgramFiles "Go\bin\go.exe"
    if (Test-Path -LiteralPath $candidate) { $Go = $candidate }
}
if (-not $Go) { throw "Go 1.23 or later is required. Install Go and retry." }
$Dotnet = (Get-Command dotnet.exe -ErrorAction SilentlyContinue).Source
if (-not $Dotnet) { throw ".NET SDK 10 is required to build the Windows app." }

if (-not $Version) { $Version = $env:VERSION }
if (-not $Version) {
    $Version = (& git -C $Root describe --tags --always --dirty 2>$null)
}
if (-not $Version) { $Version = "0.1.0-dev" }
$SafeVersion = ($Version -replace "[^A-Za-z0-9._-]", "-")
$Commit = (& git -C $Root rev-parse --short HEAD 2>$null)
if (-not $Commit) { $Commit = "unknown" }
$Date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$Package = "github.com/paddman/NTAgentShield/internal/buildinfo"
$LdFlags = "-s -w -X $Package.Version=$Version -X $Package.Commit=$Commit -X $Package.Date=$Date"

if (Test-Path -LiteralPath $OutputPath) {
    Remove-Item -LiteralPath $OutputPath -Recurse -Force
}
$Stage = Join-Path $OutputPath "package"
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

$oldGoOs = $env:GOOS
$oldGoArch = $env:GOARCH
$oldCgoEnabled = $env:CGO_ENABLED
try {
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    $builds = @(
        @{ Name = "ntagentshield-agent-windows-amd64.exe"; Package = "./cmd/ntagentshield-agent" },
        @{ Name = "ntagentshieldctl-windows-amd64.exe"; Package = "./cmd/ntagentshieldctl" },
        @{ Name = "ntagentshield-inventory-windows-amd64.exe"; Package = "./cmd/ntagentshield-inventory" },
        @{ Name = "ntagentshield-enroll-windows-amd64.exe"; Package = "./cmd/ntagentshield-enroll" },
        @{ Name = "ntagentshield-updater-windows-amd64.exe"; Package = "./cmd/ntagentshield-updater" }
    )
    foreach ($build in $builds) {
        $target = Join-Path $Stage $build.Name
        & $Go build -trimpath -ldflags $LdFlags -o $target $build.Package
        if ($LASTEXITCODE -ne 0) { throw "Go build failed for $($build.Package)" }
    }
} finally {
    if ($null -eq $oldGoOs) { Remove-Item Env:GOOS -ErrorAction SilentlyContinue } else { $env:GOOS = $oldGoOs }
    if ($null -eq $oldGoArch) { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue } else { $env:GOARCH = $oldGoArch }
    if ($null -eq $oldCgoEnabled) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $oldCgoEnabled }
}

$appProject = Join-Path $RepoRoot "app\NTAgentShield.App\NTAgentShield.App.csproj"
$appTarget = Join-Path $Stage "NTAgentShield.App.exe"
& $Dotnet publish $appProject -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -o $Stage
if ($LASTEXITCODE -ne 0) { throw "Windows app publish failed" }
if (-not (Test-Path -LiteralPath $appTarget -PathType Leaf)) {
    throw "Windows app publish did not create $appTarget"
}

New-Item -ItemType Directory -Force -Path (Join-Path $Stage "config"), (Join-Path $Stage "policies") | Out-Null
Copy-Item (Join-Path $Root "config\windows.example.json") (Join-Path $Stage "config\windows.example.json") -Force
Copy-Item (Join-Path $Root "policies\default-policy.json") (Join-Path $Stage "policies\default-policy.json") -Force
Copy-Item (Join-Path $PSScriptRoot "install.ps1") (Join-Path $Stage "install.ps1") -Force
Copy-Item (Join-Path $PSScriptRoot "uninstall-service.ps1") (Join-Path $Stage "uninstall.ps1") -Force
Copy-Item (Join-Path $PSScriptRoot "uninstall-service.ps1") (Join-Path $Stage "uninstall-service.ps1") -Force
Copy-Item (Join-Path $PSScriptRoot "README.md") (Join-Path $Stage "README.md") -Force
Copy-Item (Join-Path $Root "LICENSE") (Join-Path $Stage "LICENSE") -Force

@{
    version = $Version
    commit = $Commit
    built_at_utc = $Date
    architecture = "windows-amd64"
    service_host = "windows-scm"
    update_manifest_schema = "ntshield-update/v1"
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Stage "VERSION.json") -Encoding UTF8

$checksumLines = Get-ChildItem -LiteralPath $Stage -Recurse -File | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
    $relative = $_.FullName.Substring($Stage.Length).TrimStart("\")
    "$hash  $relative"
}
$checksumLines | Set-Content -LiteralPath (Join-Path $Stage "SHA256SUMS.txt") -Encoding ASCII

$zipPath = Join-Path $OutputPath "ntagentshield-windows-amd64-$SafeVersion.zip"
Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $zipPath -CompressionLevel Optimal -Force

Write-Host "Windows package created: $zipPath"
Write-Host "Install: powershell -ExecutionPolicy Bypass -File .\install.ps1"
