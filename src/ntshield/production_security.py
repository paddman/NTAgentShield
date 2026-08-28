from __future__ import annotations

import json
import re
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

from ntshield.audit_ledger import AuditLedger, AuditLedgerError
from ntshield.ingest_security import (
    IngestSecurityError,
    extract_tenant_ids,
    sanitize_json_document,
    validate_ingest_document,
)
from ntshield.metrics import MetricsRegistry
from ntshield.operator_auth import (
    AuthenticationError,
    AuthorizationError,
    OperatorTokenManager,
    Principal,
    parse_bearer_header,
)
from ntshield.production_config import ProductionSecurityConfig
from ntshield.rate_limit import FixedWindowRateLimiter

ASGIApp = Callable[[dict[str, Any], Callable[..., Awaitable[dict[str, Any]]], Callable[..., Awaitable[None]]], Awaitable[None]]
TenantResolver = Callable[[str], str | None]
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:@/+-]{1,128}$")
_INCIDENT_PATH_RE = re.compile(r"^/v1/incidents/[^/]+(?:/analyze)?$")
_RESPONSE_PATH_RE = re.compile(r"^/v1/operator/responses/[^/]+(?:/approve)?$")
_JSON_WRITE_PATHS = {
    "/v1/events/normalized",
    "/v1/events/raw",
    "/v1/events/bulk",
    "/v1/events/raw/bulk",
    "/v1/ingest/async/normalized",
    "/v1/ingest/async/raw",
    "/v1/operator/responses",
}


@dataclass(frozen=True, slots=True)
class RoutePolicy:
    permission: str | None
    public: bool = False
    agent_authenticated: bool = False
    rate_class: str = "read"


class ProductionSecurityMiddleware:
    """Fail-closed operator authentication and tenant authorization boundary."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: ProductionSecurityConfig,
        token_manager: OperatorTokenManager | None,
        audit_ledger: AuditLedger,
        metrics: MetricsRegistry,
        tenant_resolver: TenantResolver | None = None,
        rate_limiter: FixedWindowRateLimiter | None = None,
    ) -> None:
        self.app = app
        self.config = config
        self.token_manager = token_manager
        self.audit = audit_ledger
        self.metrics = metrics
        self.tenant_resolver = tenant_resolver
        self.rate_limiter = rate_limiter or FixedWindowRateLimiter()

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "GET")).upper()
        path = str(scope.get("path", "/"))
        policy = route_policy(method, path, metrics_public=self.config.metrics_public)
        request_id = _request_id(scope)
        timer = self.metrics.start_timer()

        if policy.public or policy.agent_authenticated:
            await self._pass_through(scope, receive, send, request_id, policy)
            self.metrics.observe_duration(
                "http_request_duration", timer, method=method, route_class=_route_class(policy)
            )
            return

        if self.config.locked or self.token_manager is None:
            await self._record_and_error(
                send,
                request_id=request_id,
                status=503,
                code="control_plane_locked",
                detail="operator security configuration is incomplete",
                actor="anonymous",
                action=f"{method} {path}",
                outcome="locked",
                payload={"lock_reasons": list(self.config.lock_reasons())},
            )
            return

        origin = _header(scope, b"origin")
        if origin and origin not in self.config.allowed_origins:
            await self._record_and_error(
                send,
                request_id=request_id,
                status=403,
                code="origin_denied",
                detail="request origin is not allowed",
                actor="anonymous",
                action=f"{method} {path}",
                outcome="denied",
            )
            return

        client_key = _client_key(scope, self.config.trust_proxy_headers)
        auth_decision = self.rate_limiter.check(
            f"auth:{client_key}", self.config.write_rate_limit_per_minute
        )
        if not auth_decision.allowed:
            await self._record_and_error(
                send,
                request_id=request_id,
                status=429,
                code="rate_limited",
                detail="authentication request rate exceeded",
                actor="anonymous",
                action=f"{method} {path}",
                outcome="rate_limited",
                extra_headers={"retry-after": str(auth_decision.retry_after_seconds)},
            )
            return

        try:
            bearer = parse_bearer_header(_header(scope, b"authorization"))
            principal = self.token_manager.verify(bearer)
            if policy.permission not in {None, "authenticated"}:
                principal.require(policy.permission)
        except AuthenticationError as exc:
            await self._record_and_error(
                send,
                request_id=request_id,
                status=401,
                code="authentication_failed",
                detail=str(exc),
                actor="anonymous",
                action=f"{method} {path}",
                outcome="denied",
                extra_headers={"www-authenticate": 'Bearer realm="NTAgentShield"'},
            )
            return
        except AuthorizationError as exc:
            await self._record_and_error(
                send,
                request_id=request_id,
                status=403,
                code="authorization_failed",
                detail=str(exc),
                actor=principal.subject,
                action=f"{method} {path}",
                outcome="denied",
                tenant_id=_single_tenant(principal.tenant_ids),
            )
            return

        body = b""
        document: Any | None = None
        redacted_fields = 0
        if _request_has_body(scope):
            try:
                body = await _read_body(receive, self.config.max_request_body_bytes)
                if body and _requires_json(method, path):
                    content_type = _header(scope, b"content-type").split(";", 1)[0].strip().lower()
                    if content_type != "application/json":
                        raise IngestSecurityError("request content-type must be application/json")
                    try:
                        document = json.loads(body)
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise IngestSecurityError("request body contains invalid JSON") from exc
                    if path.startswith("/v1/events/") or path.startswith("/v1/ingest/async/"):
                        validate_ingest_document(path, document)
                    result = sanitize_json_document(
                        document,
                        max_depth=self.config.max_json_depth,
                        max_items=self.config.max_json_items,
                        max_string_chars=self.config.max_string_chars,
                    )
                    document = result.value
                    redacted_fields = result.redacted_fields
                    body = json.dumps(
                        document,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
            except IngestSecurityError as exc:
                await self._record_and_error(
                    send,
                    request_id=request_id,
                    status=422,
                    code="ingest_boundary_rejected",
                    detail=str(exc),
                    actor=principal.subject,
                    action=f"{method} {path}",
                    outcome="rejected",
                )
                return
            except RequestBodyTooLarge as exc:
                await self._record_and_error(
                    send,
                    request_id=request_id,
                    status=413,
                    code="request_too_large",
                    detail=str(exc),
                    actor=principal.subject,
                    action=f"{method} {path}",
                    outcome="rejected",
                )
                return

        try:
            tenant_ids = _tenant_ids(scope, path, document, self.tenant_resolver)
            for tenant_id in tenant_ids:
                principal.require(policy.permission or "read", tenant_id)
        except AuthorizationError as exc:
            await self._record_and_error(
                send,
                request_id=request_id,
                status=403,
                code="tenant_access_denied",
                detail=str(exc),
                actor=principal.subject,
                action=f"{method} {path}",
                outcome="denied",
                tenant_id=next(iter(tenant_ids), None) if "tenant_ids" in locals() else None,
            )
            return

        rate_limit = _rate_limit(self.config, policy.rate_class)
        tenant_key = ",".join(sorted(tenant_ids)) or "none"
        decision = self.rate_limiter.check(
            f"operator:{principal.subject}:{policy.rate_class}:{tenant_key}", rate_limit
        )
        if not decision.allowed:
            await self._record_and_error(
                send,
                request_id=request_id,
                status=429,
                code="rate_limited",
                detail="operator request rate exceeded",
                actor=principal.subject,
                action=f"{method} {path}",
                outcome="rate_limited",
                tenant_id=next(iter(tenant_ids), None),
                extra_headers={"retry-after": str(decision.retry_after_seconds)},
            )
            return

        scope = dict(scope)
        state = dict(scope.get("state") or {})
        state.update(
            {
                "principal": principal,
                "request_id": request_id,
                "tenant_ids": tenant_ids,
                "redacted_fields": redacted_fields,
            }
        )
        scope["state"] = state
        replay_receive = _body_receive(body)
        buffered: list[dict[str, Any]] = []

        async def buffered_send(message: dict[str, Any]) -> None:
            buffered.append(message)

        status = 500
        try:
            await self.app(scope, replay_receive, buffered_send)
            status = _response_status(buffered)
        except Exception:
            buffered = [_json_start(500, request_id), _json_body({
                "error": "internal_server_error",
                "detail": "request failed inside the control plane",
                "request_id": request_id,
            })]
            status = 500

        outcome = "allowed" if status < 400 else "failed"
        audit_payload = {
            "method": method,
            "path": path,
            "permission": policy.permission,
            "status": status,
            "token_id": principal.token_id,
            "redacted_fields": redacted_fields,
        }
        try:
            self.audit.append(
                actor=principal.subject,
                action=f"{method} {path}",
                resource_type="http_request",
                request_id=request_id,
                outcome=outcome,
                tenant_id=next(iter(tenant_ids), None) if len(tenant_ids) == 1 else None,
                payload=audit_payload,
            )
        except AuditLedgerError:
            self.metrics.inc("audit_append_failures_total")
            if self.config.audit_fail_closed:
                await _send_json(
                    send,
                    503,
                    {
                        "error": "audit_unavailable",
                        "detail": "the request was not released because audit persistence failed",
                        "request_id": request_id,
                    },
                    request_id=request_id,
                )
                return

        self.metrics.inc(
            "http_requests_total",
            method=method,
            status=str(status),
            route_class=_route_class(policy),
        )
        if redacted_fields:
            self.metrics.inc("ingest_redactions_total", redacted_fields)
        self.metrics.observe_duration(
            "http_request_duration", timer, method=method, route_class=_route_class(policy)
        )
        await _flush_messages(send, buffered, request_id)

    async def _pass_through(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Any],
        send: Callable[..., Any],
        request_id: str,
        policy: RoutePolicy,
    ) -> None:
        async def secure_send(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                message = dict(message)
                message["headers"] = _security_headers(
                    list(message.get("headers") or []), request_id, scope
                )
            await send(message)

        self.metrics.inc("http_requests_total", method=scope.get("method", "GET"), status="pass", route_class=_route_class(policy))
        await self.app(scope, receive, secure_send)

    async def _record_and_error(
        self,
        send: Callable[..., Any],
        *,
        request_id: str,
        status: int,
        code: str,
        detail: str,
        actor: str,
        action: str,
        outcome: str,
        tenant_id: str | None = None,
        payload: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        try:
            self.audit.append(
                actor=actor,
                action=action,
                resource_type="security_boundary",
                request_id=request_id,
                outcome=outcome,
                tenant_id=tenant_id,
                payload={"status": status, "code": code, **(payload or {})},
            )
        except AuditLedgerError:
            self.metrics.inc("audit_append_failures_total")
            if self.config.audit_fail_closed:
                status = 503
                code = "audit_unavailable"
                detail = "security audit persistence is unavailable"
        self.metrics.inc("security_boundary_decisions_total", outcome=outcome, code=code)
        await _send_json(
            send,
            status,
            {"error": code, "detail": detail, "request_id": request_id},
            request_id=request_id,
            extra_headers=extra_headers,
        )


class RequestBodyTooLarge(ValueError):
    pass


def route_policy(method: str, path: str, *, metrics_public: bool = False) -> RoutePolicy:
    if path in {"/", "/live", "/ready", "/favicon.ico"} or path.startswith("/static/"):
        return RoutePolicy(None, public=True)
    if path == "/v1/enrollment" or path.startswith("/v1/agent/"):
        return RoutePolicy(None, agent_authenticated=True, rate_class="agent")
    if path == "/metrics":
        return RoutePolicy(None if metrics_public else "metrics.read", public=metrics_public)
    if path == "/v1/operator/whoami":
        return RoutePolicy("authenticated")
    if path.startswith("/v1/operator/audit"):
        return RoutePolicy("audit.read")
    if path == "/v1/operator/agents":
        return RoutePolicy("fleet.read")
    if path == "/v1/operator/responses" and method == "POST":
        return RoutePolicy("respond.propose", rate_class="write")
    if _RESPONSE_PATH_RE.fullmatch(path):
        if method == "POST" and path.endswith("/approve"):
            return RoutePolicy("respond.approve", rate_class="write")
        return RoutePolicy("read")
    if path in {"/v1/events/normalized", "/v1/events/raw", "/v1/events/bulk", "/v1/events/raw/bulk"}:
        return RoutePolicy("ingest", rate_class="ingest")
    if path.startswith("/v1/ingest/async/"):
        return RoutePolicy("ingest", rate_class="ingest")
    if _INCIDENT_PATH_RE.fullmatch(path) and method == "POST" and path.endswith("/analyze"):
        return RoutePolicy("analyze", rate_class="write")
    if path.startswith("/v1/findings") or path.startswith("/v1/incidents"):
        return RoutePolicy("read")
    if path in {"/v1/stats", "/v1/coverage", "/health", "/openapi.json", "/docs", "/redoc"}:
        return RoutePolicy("read")
    if path.startswith("/v1/"):
        return RoutePolicy("platform.admin", rate_class="write" if method != "GET" else "read")
    return RoutePolicy("read")


def _tenant_ids(
    scope: dict[str, Any],
    path: str,
    document: Any | None,
    resolver: TenantResolver | None,
) -> frozenset[str]:
    values: set[str] = set()
    query = parse_qs(bytes(scope.get("query_string") or b"").decode("utf-8", "replace"))
    for key in ("tenant_id", "tenant"):
        for value in query.get(key, []):
            value = value.strip()
            if value:
                values.add(value)
    values.update(extract_tenant_ids(path, document))
    if resolver is not None and (_INCIDENT_PATH_RE.fullmatch(path) or _RESPONSE_PATH_RE.fullmatch(path)):
        resolved = resolver(path)
        if resolved:
            values.add(resolved)
    return frozenset(values)


def _rate_limit(config: ProductionSecurityConfig, rate_class: str) -> int:
    if rate_class == "ingest":
        return config.ingest_rate_limit_per_minute
    if rate_class == "write":
        return config.write_rate_limit_per_minute
    return config.read_rate_limit_per_minute


def _requires_json(method: str, path: str) -> bool:
    if method not in {"POST", "PUT", "PATCH"}:
        return False
    return path in _JSON_WRITE_PATHS or path.endswith("/approve")


def _request_has_body(scope: dict[str, Any]) -> bool:
    method = str(scope.get("method", "GET")).upper()
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    content_length = _header(scope, b"content-length")
    return not content_length or content_length != "0"


async def _read_body(receive: Callable[..., Any], limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message.get("type") == "http.disconnect":
            break
        if message.get("type") != "http.request":
            continue
        chunk = bytes(message.get("body") or b"")
        total += len(chunk)
        if total > limit:
            raise RequestBodyTooLarge(f"request body exceeds {limit} bytes")
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _body_receive(body: bytes) -> Callable[..., Awaitable[dict[str, Any]]]:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    return receive


def _request_id(scope: dict[str, Any]) -> str:
    candidate = _header(scope, b"x-request-id")
    return candidate if _REQUEST_ID_RE.fullmatch(candidate) else uuid.uuid4().hex


def _client_key(scope: dict[str, Any], trust_proxy_headers: bool) -> str:
    if trust_proxy_headers:
        forwarded = _header(scope, b"x-forwarded-for").split(",", 1)[0].strip()
        if forwarded:
            return forwarded[:128]
    client = scope.get("client")
    return str(client[0])[:128] if isinstance(client, (list, tuple)) and client else "unknown"


def _header(scope: dict[str, Any], name: bytes) -> str:
    for key, value in scope.get("headers") or []:
        if bytes(key).lower() == name:
            return bytes(value).decode("latin-1")
    return ""


def _response_status(messages: list[dict[str, Any]]) -> int:
    for message in messages:
        if message.get("type") == "http.response.start":
            return int(message.get("status", 500))
    return 500


async def _flush_messages(send: Callable[..., Any], messages: list[dict[str, Any]], request_id: str) -> None:
    for message in messages:
        if message.get("type") == "http.response.start":
            message = dict(message)
            message["headers"] = _security_headers(list(message.get("headers") or []), request_id, None)
        await send(message)


def _security_headers(
    headers: list[tuple[bytes, bytes]], request_id: str, scope: dict[str, Any] | None
) -> list[tuple[bytes, bytes]]:
    remove = {
        b"x-content-type-options",
        b"x-frame-options",
        b"referrer-policy",
        b"permissions-policy",
        b"x-request-id",
    }
    secured = [(key, value) for key, value in headers if bytes(key).lower() not in remove]
    secured.extend(
        [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
            (b"x-request-id", request_id.encode("ascii")),
        ]
    )
    if scope is not None and scope.get("scheme") == "https":
        secured.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
    return secured


async def _send_json(
    send: Callable[..., Any],
    status: int,
    payload: dict[str, Any],
    *,
    request_id: str,
    extra_headers: dict[str, str] | None = None,
) -> None:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = [
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    for key, value in (extra_headers or {}).items():
        headers.append((key.lower().encode("ascii"), value.encode("latin-1")))
    headers = _security_headers(headers, request_id, None)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _json_start(status: int, request_id: str) -> dict[str, Any]:
    return {
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json; charset=utf-8")],
    }


def _json_body(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "http.response.body",
        "body": json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        "more_body": False,
    }


def _single_tenant(tenants: frozenset[str]) -> str | None:
    return next(iter(tenants)) if len(tenants) == 1 else None


def _route_class(policy: RoutePolicy) -> str:
    if policy.public:
        return "public"
    if policy.agent_authenticated:
        return "agent"
    return policy.rate_class
