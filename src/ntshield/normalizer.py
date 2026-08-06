from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any
from uuid import uuid4

from ntshield.models import (
    ActorContext,
    AssetContext,
    DatabaseContext,
    FileContext,
    NetworkContext,
    ProcessContext,
    RawEventEnvelope,
    SecurityEvent,
    ServiceContext,
    WebContext,
)


def _basename(value: str | None) -> str | None:
    if not value:
        return None
    return re.split(r"[\\/]", value)[-1]


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_external(value: str | None) -> bool | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_private or address.is_loopback or address.is_link_local)
    except ValueError:
        return None


def _time(envelope: RawEventEnvelope, data: dict[str, Any]) -> datetime:
    value = envelope.observed_at or data.get("observed_at") or data.get("timestamp")
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _base(envelope: RawEventEnvelope, event_type: str) -> dict[str, Any]:
    return {
        "event_id": str(uuid4()),
        "tenant_id": envelope.tenant_id,
        "observed_at": _time(envelope, envelope.data),
        "source_type": envelope.source_type,
        "event_type": event_type,
        "asset": AssetContext(
            id=envelope.asset_id,
            hostname=envelope.data.get("Computer") or envelope.data.get("hostname"),
            role=envelope.asset_role,
            criticality=envelope.asset_criticality,
        ),
        "raw": envelope.data,
    }


def normalize(envelope: RawEventEnvelope) -> SecurityEvent:
    source = envelope.source_type.casefold()
    if source == "normalized":
        payload = dict(envelope.data)
        payload.setdefault("tenant_id", envelope.tenant_id)
        payload.setdefault("source_type", "normalized")
        payload.setdefault("observed_at", _time(envelope, payload))
        payload.setdefault(
            "asset",
            {
                "id": envelope.asset_id,
                "role": envelope.asset_role,
                "criticality": envelope.asset_criticality,
            },
        )
        return SecurityEvent.model_validate(payload)
    if source in {"sysmon", "windows_sysmon"}:
        return _normalize_sysmon(envelope)
    if source in {"windows_security", "wineventlog"}:
        return _normalize_windows_security(envelope)
    if source in {"nginx", "iis", "apache"}:
        return _normalize_web(envelope)
    if source in {"mysql", "mysql_audit", "postgresql", "mssql"}:
        return _normalize_database(envelope)
    if source in {"auditd", "linux_auditd"}:
        return _normalize_auditd(envelope)
    raise ValueError(f"Unsupported source_type: {envelope.source_type}")


def _normalize_sysmon(envelope: RawEventEnvelope) -> SecurityEvent:
    data = envelope.data
    event_id = _integer(data.get("EventID") or data.get("event_id"))
    mapping = {
        1: "process.start",
        3: "network.connect",
        6: "driver.load",
        10: "process.access",
        11: "file.create",
        13: "registry.modify",
        22: "dns.query",
        23: "file.delete",
        25: "process.tamper",
    }
    payload = _base(envelope, mapping.get(event_id, "windows.sysmon"))
    image = data.get("Image") or data.get("image")
    parent = data.get("ParentImage") or data.get("parent_image")
    destination = data.get("DestinationIp") or data.get("destination_ip")
    target_file = data.get("TargetFilename") or data.get("target_filename")
    payload.update(
        actor=ActorContext(user=data.get("User") or data.get("user")),
        process=ProcessContext(
            name=_basename(image),
            path=image,
            pid=_integer(data.get("ProcessId") or data.get("process_id")),
            parent_name=_basename(parent),
            parent_path=parent,
            parent_pid=_integer(data.get("ParentProcessId") or data.get("parent_process_id")),
            command_line=data.get("CommandLine") or data.get("command_line"),
            sha256=data.get("SHA256") or data.get("sha256"),
        ),
        network=NetworkContext(
            source_ip=data.get("SourceIp") or data.get("source_ip"),
            source_port=_integer(data.get("SourcePort") or data.get("source_port")),
            destination_ip=destination,
            destination_port=_integer(
                data.get("DestinationPort") or data.get("destination_port")
            ),
            protocol=data.get("Protocol") or data.get("protocol"),
            direction="outbound" if destination else None,
            is_external=_is_external(destination),
            domain=data.get("QueryName") or data.get("domain"),
        ),
        file=FileContext(
            path=target_file,
            operation="create" if event_id == 11 else None,
            extension=PurePath(target_file).suffix.casefold() if target_file else None,
        ),
        message=data.get("Message") or data.get("message"),
    )
    return SecurityEvent.model_validate(payload)


def _normalize_windows_security(envelope: RawEventEnvelope) -> SecurityEvent:
    data = envelope.data
    event_id = _integer(data.get("EventID") or data.get("event_id"))
    mapping = {
        4624: "auth.logon",
        4625: "auth.logon_failed",
        4648: "auth.explicit_credentials",
        4672: "privilege.special_logon",
        4688: "process.start",
        4697: "service.create",
        4698: "persistence.scheduled_task",
        4720: "identity.account_create",
        5156: "network.connect",
        5157: "network.block",
        1102: "security.log_clear",
        7045: "service.create",
    }
    payload = _base(envelope, mapping.get(event_id, "windows.security"))
    image = data.get("NewProcessName") or data.get("Image")
    parent = data.get("ParentProcessName") or data.get("ParentImage")
    destination = data.get("DestAddress") or data.get("DestinationIp")
    service_binary = data.get("ServiceFileName") or data.get("ImagePath")
    payload.update(
        actor=ActorContext(
            user=data.get("TargetUserName") or data.get("SubjectUserName"),
            domain=data.get("TargetDomainName") or data.get("SubjectDomainName"),
            logon_type=str(data.get("LogonType")) if data.get("LogonType") is not None else None,
        ),
        process=ProcessContext(
            name=_basename(image),
            path=image,
            parent_name=_basename(parent),
            parent_path=parent,
            command_line=data.get("CommandLine") or data.get("ProcessCommandLine"),
        ),
        network=NetworkContext(
            source_ip=data.get("IpAddress") or data.get("SourceAddress"),
            source_port=_integer(data.get("IpPort") or data.get("SourcePort")),
            destination_ip=destination,
            destination_port=_integer(data.get("DestPort") or data.get("DestinationPort")),
            is_external=_is_external(destination),
        ),
        service=ServiceContext(
            name=data.get("ServiceName"),
            binary_path=service_binary,
            action="create" if event_id in {4697, 7045} else None,
        ),
        outcome="failure" if event_id == 4625 else "success",
        message=data.get("Message"),
    )
    return SecurityEvent.model_validate(payload)


def _normalize_web(envelope: RawEventEnvelope) -> SecurityEvent:
    data = envelope.data
    source_ip = data.get("remote_addr") or data.get("c-ip") or data.get("client_ip")
    method = data.get("request_method") or data.get("cs-method") or data.get("method")
    path = data.get("uri") or data.get("cs-uri-stem") or data.get("path")
    status = _integer(data.get("status") or data.get("sc-status"))
    payload = _base(envelope, "web.request")
    payload.update(
        network=NetworkContext(source_ip=source_ip, direction="inbound"),
        web=WebContext(
            method=method,
            path=path,
            route=data.get("route") or path,
            status=status,
            user_agent=data.get("http_user_agent") or data.get("cs(User-Agent)"),
            request_id=data.get("request_id"),
            payload_novelty=data.get("payload_novelty"),
        ),
        outcome="error" if status and status >= 500 else "success",
        message=data.get("request") or data.get("message"),
    )
    return SecurityEvent.model_validate(payload)


def _normalize_database(envelope: RawEventEnvelope) -> SecurityEvent:
    data = envelope.data
    statement = data.get("statement") or data.get("query") or data.get("sql_text")
    payload = _base(envelope, "database.query")
    payload.update(
        actor=ActorContext(user=data.get("user") or data.get("db_user")),
        network=NetworkContext(source_ip=data.get("client_ip") or data.get("host")),
        database=DatabaseContext(
            engine=envelope.source_type,
            database=data.get("database") or data.get("db"),
            statement=statement,
            query_shape=data.get("query_shape"),
            rows=_integer(data.get("rows") or data.get("rows_examined")),
            sensitivity=data.get("sensitivity"),
            duration_ms=data.get("duration_ms"),
        ),
        outcome=data.get("status") or data.get("outcome"),
        message=data.get("message"),
    )
    return SecurityEvent.model_validate(payload)


def _normalize_auditd(envelope: RawEventEnvelope) -> SecurityEvent:
    data = envelope.data
    syscall = str(data.get("syscall") or data.get("SYSCALL") or "").casefold()
    event_type = "process.start" if syscall in {"execve", "execveat"} else "linux.audit"
    if syscall in {"socket", "socketcall"} and str(data.get("socket_type", "")).casefold() in {
        "sock_raw",
        "raw",
    }:
        event_type = "network.raw_socket_open"
    executable = data.get("exe") or data.get("executable")
    payload = _base(envelope, event_type)
    payload.update(
        actor=ActorContext(user=str(data.get("uid") or data.get("auid") or "") or None),
        process=ProcessContext(
            name=_basename(executable),
            path=executable,
            pid=_integer(data.get("pid")),
            parent_pid=_integer(data.get("ppid")),
            command_line=data.get("cmdline") or data.get("command"),
        ),
        message=data.get("msg") or data.get("message"),
    )
    return SecurityEvent.model_validate(payload)
