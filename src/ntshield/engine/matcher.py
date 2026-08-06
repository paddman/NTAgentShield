from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any


def get_field(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, Mapping):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


def _normalise(value: Any) -> Any:
    return value.casefold() if isinstance(value, str) else value


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def compare(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "exists":
        return (actual is not None) is bool(expected)
    if actual is None:
        return False

    if operator == "eq":
        return _normalise(actual) == _normalise(expected)
    if operator == "ne":
        return _normalise(actual) != _normalise(expected)
    if operator in {"in", "not_in"}:
        options = {_normalise(item) for item in _as_list(expected)}
        result = _normalise(actual) in options
        return not result if operator == "not_in" else result
    if operator in {"contains", "icontains"}:
        if isinstance(actual, list):
            result = any(_normalise(item) == _normalise(expected) for item in actual)
        else:
            left = str(actual)
            right = str(expected)
            if operator == "icontains":
                left, right = left.casefold(), right.casefold()
            result = right in left
        return result
    if operator == "one_of_contains":
        text = str(actual).casefold()
        return any(str(item).casefold() in text for item in _as_list(expected))
    if operator == "startswith":
        return str(actual).casefold().startswith(str(expected).casefold())
    if operator == "endswith":
        return str(actual).casefold().endswith(str(expected).casefold())
    if operator == "regex":
        return re.search(str(expected), str(actual), flags=re.IGNORECASE) is not None
    if operator in {"gt", "gte", "lt", "lte"}:
        try:
            left, right = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[operator]
    if operator == "cidr":
        try:
            address = ipaddress.ip_address(str(actual))
            return any(address in ipaddress.ip_network(item, strict=False) for item in _as_list(expected))
        except ValueError:
            return False
    if operator == "not_cidr":
        try:
            address = ipaddress.ip_address(str(actual))
            return all(address not in ipaddress.ip_network(item, strict=False) for item in _as_list(expected))
        except ValueError:
            return False
    raise ValueError(f"Unsupported matcher operator: {operator}")


def matches(data: Any, conditions: dict[str, Any]) -> bool:
    for expression, expected in conditions.items():
        if "|" in expression:
            field_path, operator = expression.rsplit("|", 1)
        else:
            field_path, operator = expression, "eq"
        if not compare(get_field(data, field_path), operator, expected):
            return False
    return True
