from __future__ import annotations

from ntshield.adapters import normalize_record


def test_sysmon_process_creation_adapter() -> None:
    event = normalize_record(
        "sysmon",
        {
            "EventID": 1,
            "UtcTime": "2026-08-06T10:00:00Z",
            "Computer": "WEB01",
            "User": "IIS APPPOOL\\DefaultAppPool",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc AAAA",
            "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
            "ProcessId": 4444,
        },
        tenant_id="tenant-a",
        asset_id="web01",
    )
    assert event.event_type == "process.start"
    assert event.process["name"] == "powershell.exe"
    assert event.parent_process["name"] == "w3wp.exe"
    assert event.tenant_id == "tenant-a"
