from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import PurePath
from typing import Any

_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-f]{16,}\b", re.IGNORECASE)
_LONG_NUMBER_RE = re.compile(r"\b\d{4,}\b")
_WS_RE = re.compile(r"\s+")


def get_path(value: Any, path: str, default: Any = None) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def safe_text(value: Any, max_chars: int = 256) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    text = text.replace("\x00", "")
    return text[:max_chars]


def normalize_name(value: Any) -> str:
    text = safe_text(value, 512).strip().lower().replace("\\", "/")
    return text.rsplit("/", 1)[-1]


def command_shape(command_line: Any) -> str:
    text = safe_text(command_line, 2048).lower()
    if not text:
        return ""
    text = _URL_RE.sub("<url>", text)
    text = _IPV4_RE.sub("<ip>", text)
    text = _HEX_RE.sub("<token>", text)
    text = _LONG_NUMBER_RE.sub("<n>", text)
    text = _WS_RE.sub(" ", text).strip()
    return text[:512]


def destination_bucket(ip_value: Any, domain_value: Any, port_value: Any) -> str:
    domain = safe_text(domain_value, 253).strip().lower().rstrip(".")
    port = safe_text(port_value, 12)
    if domain:
        return f"{domain}:{port}"
    ip_text = safe_text(ip_value, 64)
    if not ip_text:
        return ""
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        prefix = 24 if ip_obj.version == 4 else 64
        network = ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False)
        return f"{network}:{port}"
    except ValueError:
        return f"{ip_text}:{port}"


def file_bucket(path_value: Any) -> str:
    text = safe_text(path_value, 1024).replace("\\", "/").lower()
    if not text:
        return ""
    path = PurePath(text)
    parent = str(path.parent)
    suffix = path.suffix or "<none>"
    parts = [part for part in parent.split("/") if part]
    parent_tail = "/".join(parts[-2:])
    return f"{parent_tail}|{suffix}"


def stable_hash(*parts: str) -> str:
    joined = "\x1f".join(parts)
    return hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()
