# NTAgentShield Windows package

This package installs the Go endpoint agent on Windows amd64.

## Build

From the `agent` directory in an elevated or normal PowerShell session:

```powershell
.\packaging\windows\build-package.ps1 -Version 0.1.0
```

The package is written to `dist\windows\ntagentshield-windows-amd64-<version>.zip`.

## Install

Extract the zip, open PowerShell as Administrator, and run:

```powershell
.\install.ps1
```

The installer:

- installs the binaries under `C:\Program Files\NTAgentShield`;
- creates the first configuration at `C:\ProgramData\NTAgentShield\agent.json`;
- preserves an existing configuration and evidence directory during upgrades;
- runs the agent as `SYSTEM` through the `NTAgentShield` Scheduled Task at startup;
- restarts the task up to three times after an unexpected exit; and
- restricts the data directory to `SYSTEM` and local Administrators.

The current Go executable is a console process, so the package uses a Scheduled Task rather than registering it directly with the Windows Service Control Manager.

To intentionally replace the existing configuration:

```powershell
.\install.ps1 -ForceConfig
```

## Uninstall

```powershell
.\uninstall-service.ps1 -RemoveFiles
```

Configuration and evidence remain under `C:\ProgramData\NTAgentShield` unless `-RemoveData` is supplied.
