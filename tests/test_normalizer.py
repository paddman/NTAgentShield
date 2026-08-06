from ntshield.models import RawEventEnvelope
from ntshield.normalizer import normalize


def test_sysmon_process_normalization() -> None:
    event = normalize(
        RawEventEnvelope(
            tenant_id="tenant-a",
            asset_id="web-01",
            asset_role="public-web",
            source_type="sysmon",
            data={
                "EventID": 1,
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentImage": r"C:\Windows\System32\inetsrv\w3wp.exe",
                "CommandLine": "powershell.exe -NoProfile",
                "User": r"IIS APPPOOL\Production",
            },
        )
    )
    assert event.event_type == "process.start"
    assert event.process.name == "powershell.exe"
    assert event.process.parent_name == "w3wp.exe"
    assert event.asset.role == "public-web"
