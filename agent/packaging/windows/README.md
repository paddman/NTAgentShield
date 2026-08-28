# NTAgentShield Windows package

The Windows amd64 package installs the Go Agent as a native Windows Service controlled by the
Service Control Manager. It no longer relies on a startup Scheduled Task. Service stop, shutdown
and preshutdown controls cancel the Agent context and allow evidence and outbox state to close
cleanly.

## Build

Requirements: Go 1.23 or later and the .NET 10 SDK.

```powershell
.\packaging\windows\build-package.ps1 -Version 0.2.0
```

The package includes the Agent, operator CLI, inventory CLI, enrollment CLI, desktop dashboard and
`ntagentshield-updater.exe`.

## Install

Run PowerShell as Administrator:

```powershell
.\install.ps1
```

To enable the updater during installation, provision the release-signing public key separately:

```powershell
.\install.ps1 -UpdatePublicKeyPath .\update-signing.pub
```

The installer:

- installs binaries under `C:\Program Files\NTAgentShield`;
- preserves configuration and evidence under `C:\ProgramData\NTAgentShield`;
- registers `NTAgentShield` as a delayed automatic Windows Service running as `LocalSystem`;
- configures three recovery restarts through SCM;
- removes the legacy Scheduled Task when upgrading;
- restricts program and data directory ACLs; and
- installs the dashboard shortcut.

## Signed update

The updater accepts only a signed `ntshield-update/v1` envelope. The envelope binds the version,
expiry, OS, architecture, HTTPS artifact URL, byte length and SHA-256 digest. The updater rejects
rollback, expired manifests, non-HTTPS URLs, cross-platform artifacts and signatures that do not
match the pinned Ed25519 public key.

```powershell
& 'C:\Program Files\NTAgentShield\ntagentshield-updater.exe' `
  --manifest-url https://updates.example/ntagentshield-agent-windows-amd64.manifest.json `
  --public-key 'C:\ProgramData\NTAgentShield\update-signing.pub' `
  --target 'C:\Program Files\NTAgentShield\ntagentshield-agent.exe'
```

The update is staged on the same volume, the service is stopped through SCM, the old executable is
retained as `.previous`, and startup failure restores the previous binary.

## Uninstall

```powershell
.\uninstall-service.ps1 -RemoveFiles
```

Add `-RemoveData` only when configuration, identity, certificates, queue and evidence should also be
deleted.
