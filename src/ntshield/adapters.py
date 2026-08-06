from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable

from .models import SecurityEvent
from .utils import normalize_name, safe_text


def _first(record: dict[str, Any], *names: str, default: Any = None) -> Any:
    lowered = {str(key).lower(): value for key, value in record.items()}
    for name in names:
        if name in record:
            return record[name]
        if name.lower() in lowered:
            return lowered[name.lower()]
    return default


def _time(record: dict[str, Any]) -> datetime:
    raw = _first(record, "observed_at", "timestamp", "@timestamp", "UtcTime", "TimeCreated")
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if raw:
        text = str(raw).replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    date = _first(record, "date")
    time = _first(record, "time")
    if date and time:
        try:
            return datetime.fromisoformat(f"{date}T{time}").replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def normalize_sysmon(
    record: dict[str, Any], *, tenant_id: str, asset_id: str
) -> SecurityEvent:
    event_id = int(_first(record, "EventID", "event_id", default=0) or 0)
    common = {
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "observed_at": _time(record),
        "source": "windows-sysmon",
        "actor": {"user": {"name": safe_text(_first(record, "User"), 256)}},
        "host": {"name": safe_text(_first(record, "Computer", "host", default=asset_id), 256)},
        "raw": safe_text(record, 8192),
        "data": {"native_event_id": event_id},
    }
    if event_id == 1:
        return SecurityEvent(
            **common,
            event_type="process.start",
            process={
                "name": normalize_name(_first(record, "Image")),
                "path": _first(record, "Image"),
                "command_line": _first(record, "CommandLine"),
                "pid": _first(record, "ProcessId"),
                "guid": _first(record, "ProcessGuid"),
                "hashes": _first(record, "Hashes"),
                "signature_status": _first(record, "SignatureStatus"),
                "signed": _first(record, "Signed"),
            },
            parent_process={
                "name": normalize_name(_first(record, "ParentImage")),
                "path": _first(record, "ParentImage"),
                "command_line": _first(record, "ParentCommandLine"),
                "pid": _first(record, "ParentProcessId"),
                "guid": _first(record, "ParentProcessGuid"),
            },
        )
    if event_id == 3:
        return SecurityEvent(
            **common,
            event_type="network.connect",
            process={
                "name": normalize_name(_first(record, "Image")),
                "path": _first(record, "Image"),
                "pid": _first(record, "ProcessId"),
                "guid": _first(record, "ProcessGuid"),
            },
            network={
                "src": {
                    "ip": _first(record, "SourceIp"),
                    "port": _first(record, "SourcePort"),
                },
                "dst": {
                    "ip": _first(record, "DestinationIp"),
                    "port": _first(record, "DestinationPort"),
                    "domain": _first(record, "DestinationHostname"),
                },
                "protocol": _first(record, "Protocol"),
                "initiated": _first(record, "Initiated"),
            },
        )
    if event_id == 11:
        target = _first(record, "TargetFilename")
        return SecurityEvent(
            **common,
            event_type="file.write",
            process={
                "name": normalize_name(_first(record, "Image")),
                "path": _first(record, "Image"),
                "pid": _first(record, "ProcessId"),
                "guid": _first(record, "ProcessGuid"),
            },
            file={"path": target},
        )
    if event_id in {12, 13, 14}:
        return SecurityEvent(
            **common,
            event_type="registry.set",
            process={
                "name": normalize_name(_first(record, "Image")),
                "path": _first(record, "Image"),
                "pid": _first(record, "ProcessId"),
                "guid": _first(record, "ProcessGuid"),
            },
            registry={
                "path": _first(record, "TargetObject"),
                "details": _first(record, "Details"),
            },
        )
    if event_id == 22:
        return SecurityEvent(
            **common,
            event_type="dns.query",
            process={
                "name": normalize_name(_first(record, "Image")),
                "path": _first(record, "Image"),
                "pid": _first(record, "ProcessId"),
                "guid": _first(record, "ProcessGuid"),
            },
            network={"dst": {"domain": _first(record, "QueryName")}},
        )
    return SecurityEvent(**common, event_type="windows.event")


def normalize_windows_event(
    record: dict[str, Any], *, tenant_id: str, asset_id: str
) -> SecurityEvent:
    native_id = int(_first(record, "EventID", "event_id", default=0) or 0)
    common = {
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "observed_at": _time(record),
        "source": "windows-eventlog",
        "host": {"name": safe_text(_first(record, "Computer", default=asset_id), 256)},
        "raw": safe_text(record, 8192),
        "data": {"native_event_id": native_id},
    }
    user = _first(record, "TargetUserName", "SubjectUserName", "User")
    src_ip = _first(record, "IpAddress", "SourceNetworkAddress")
    if native_id in {4624, 4625}:
        return SecurityEvent(
            **common,
            event_type="auth.success" if native_id == 4624 else "auth.failure",
            actor={"user": {"name": user}},
            auth={
                "src_ip": src_ip,
                "logon_type": _first(record, "LogonType"),
                "process": _first(record, "ProcessName"),
                "workstation": _first(record, "WorkstationName"),
            },
        )
    if native_id == 4688:
        return SecurityEvent(
            **common,
            event_type="process.start",
            actor={"user": {"name": user}},
            process={
                "name": normalize_name(_first(record, "NewProcessName")),
                "path": _first(record, "NewProcessName"),
                "command_line": _first(record, "CommandLine", "ProcessCommandLine"),
                "pid": _first(record, "NewProcessId"),
            },
            parent_process={
                "name": normalize_name(_first(record, "ParentProcessName")),
                "path": _first(record, "ParentProcessName"),
                "pid": _first(record, "ProcessId"),
            },
        )
    if native_id in {4697, 7045}:
        return SecurityEvent(
            **common,
            event_type="service.install",
            actor={"user": {"name": user}},
            service={
                "name": _first(record, "ServiceName"),
                "image_path": _first(record, "ServiceFileName", "ImagePath"),
                "start_type": _first(record, "ServiceStartType", "StartType"),
                "account": _first(record, "ServiceAccount", "AccountName"),
            },
            process={
                "name": normalize_name(_first(record, "ServiceFileName", "ImagePath")),
                "path": _first(record, "ServiceFileName", "ImagePath"),
            },
        )
    return SecurityEvent(
        **common,
        event_type="windows.event",
        actor={"user": {"name": user}},
        auth={"src_ip": src_ip},
    )


def normalize_web_access(
    record: dict[str, Any], *, tenant_id: str, asset_id: str, source: str
) -> SecurityEvent:
    return SecurityEvent(
        tenant_id=tenant_id,
        asset_id=asset_id,
        observed_at=_time(record),
        event_type="web.request",
        source=source,
        host={"name": safe_text(_first(record, "host", "s-computername", default=asset_id), 256)},
        actor={"user": {"name": _first(record, "user", "cs-username")}},
        network={
            "src": {
                "ip": _first(record, "remote_addr", "c-ip", "client_ip"),
                "port": _first(record, "remote_port"),
            },
            "dst": {"ip": _first(record, "server_addr", "s-ip")},
            "bytes_out": _first(record, "body_bytes_sent", "sc-bytes"),
        },
        http={
            "method": _first(record, "request_method", "cs-method", "method"),
            "path": _first(record, "uri", "cs-uri-stem", "path"),
            "query": _first(record, "args", "cs-uri-query", "query"),
            "status": _first(record, "status", "sc-status"),
            "user_agent": _first(record, "http_user_agent", "cs(User-Agent)", "user_agent"),
            "referer": _first(record, "http_referer", "cs(Referer)", "referer"),
            "request_time": _first(record, "request_time", "time-taken"),
        },
        raw=safe_text(record, 8192),
    )


def normalize_linux_auditd(
    record: dict[str, Any], *, tenant_id: str, asset_id: str
) -> SecurityEvent:
    record_type = str(_first(record, "type", default="")).upper()
    process_name = normalize_name(_first(record, "exe", "comm"))
    command_line = _first(record, "command_line", "cmd", "proctitle")
    common = {
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "observed_at": _time(record),
        "source": "linux-auditd",
        "actor": {
            "user": {
                "name": _first(record, "acct", "user"),
                "uid": _first(record, "uid"),
                "auid": _first(record, "auid"),
            }
        },
        "host": {"name": _first(record, "node", "hostname", default=asset_id)},
        "raw": safe_text(record, 8192),
        "data": {"audit_type": record_type, "syscall": _first(record, "syscall")},
    }
    if record_type in {"EXECVE", "SYSCALL", "PROCTITLE"} and (
        command_line or _first(record, "exe")
    ):
        return SecurityEvent(
            **common,
            event_type="process.start",
            process={
                "name": process_name,
                "path": _first(record, "exe"),
                "command_line": command_line,
                "pid": _first(record, "pid"),
                "ppid": _first(record, "ppid"),
            },
            parent_process={
                "name": normalize_name(_first(record, "parent_exe", "parent_comm")),
                "path": _first(record, "parent_exe"),
                "pid": _first(record, "ppid"),
            },
        )
    if record_type in {"PATH", "CWD"}:
        return SecurityEvent(
            **common,
            event_type="file.write",
            process={"name": process_name, "path": _first(record, "exe")},
            file={
                "path": _first(record, "name", "path"),
                "mode": _first(record, "mode"),
                "inode": _first(record, "inode"),
            },
        )
    if record_type in {"SOCKADDR", "NETFILTER_PKT"}:
        return SecurityEvent(
            **common,
            event_type="network.connect",
            process={"name": process_name, "path": _first(record, "exe")},
            network={
                "src": {"ip": _first(record, "src", "saddr")},
                "dst": {
                    "ip": _first(record, "dst", "daddr"),
                    "port": _first(record, "dport"),
                },
            },
        )
    return SecurityEvent(**common, event_type="linux.audit")


Adapter = Callable[..., SecurityEvent]


def normalize_record(
    adapter: str, record: dict[str, Any], *, tenant_id: str, asset_id: str
) -> SecurityEvent:
    normalized = adapter.strip().lower()
    if normalized == "sysmon":
        return normalize_sysmon(record, tenant_id=tenant_id, asset_id=asset_id)
    if normalized in {"windows", "windows-eventlog"}:
        return normalize_windows_event(record, tenant_id=tenant_id, asset_id=asset_id)
    if normalized in {"iis", "nginx", "apache"}:
        return normalize_web_access(
            record,
            tenant_id=tenant_id,
            asset_id=asset_id,
            source=f"{normalized}-access",
        )
    if normalized in {"auditd", "linux-auditd"}:
        return normalize_linux_auditd(record, tenant_id=tenant_id, asset_id=asset_id)
    raise ValueError(f"Unsupported adapter: {adapter}")
