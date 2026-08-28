"""Identity-bound MCP tools for Central response orchestration.

MCP may propose one typed action, but it never exposes an approval tool. Approval
must pass through the authenticated operator API where the approver identity,
tenant scope, exact action digest and audit chain are enforced independently.
"""

from __future__ import annotations

import os
from typing import Any, Literal

from ntshield.operator_auth import OperatorTokenManager, Principal
from ntshield.production_config import ProductionSecurityConfig
from ntshield.response_broker import ResponseAction, ResponseBrokerStore
from ntshield.response_identity import response_action_summary as _response_action_summary
from ntshield.settings import Settings


def build_firewall_port_args(
    operation: str,
    protocol: str,
    direction: str,
    port: int,
) -> dict[str, Any]:
    operation = operation.strip().lower()
    if operation not in {"open", "close"}:
        raise ValueError("operation must be open or close")
    protocol = protocol.strip().upper()
    if protocol not in {"TCP", "UDP"}:
        raise ValueError("protocol must be TCP or UDP")
    direction = direction.strip().lower()
    if direction not in {"inbound", "outbound"}:
        raise ValueError("direction must be inbound or outbound")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return {
        "operation": operation,
        "protocol": protocol,
        "direction": direction,
        "port": port,
    }


def response_action_summary(action: ResponseAction) -> dict[str, Any]:
    """Compatibility export with the exact approval digest included."""

    return _response_action_summary(action)


def propose_firewall_port(
    store: ResponseBrokerStore,
    *,
    tenant_id: str,
    agent_id: str,
    operation: str,
    protocol: str,
    direction: str,
    port: int,
    reason: str,
    requested_by: str | None = None,
    principal: Principal | None = None,
    ttl_seconds: int = 300,
    incident_id: str | None = None,
) -> dict[str, Any]:
    if principal is not None:
        principal.require("respond.propose", tenant_id)
        requester = principal.subject
    elif requested_by:
        # Kept only for direct library compatibility and unit tests. MCP itself
        # always supplies a cryptographically authenticated Principal.
        requester = requested_by.strip()
    else:
        raise ValueError("an authenticated principal is required")
    args = build_firewall_port_args(operation, protocol, direction, port)
    action = store.create_action(
        tenant_id=tenant_id,
        agent_id=agent_id,
        tool="firewall.port",
        args=args,
        reason=reason,
        requested_by=requester,
        ttl_seconds=ttl_seconds,
        incident_id=incident_id,
    )
    summary = response_action_summary(action)
    summary["next_step"] = (
        "อนุมัติผ่าน POST /v1/operator/responses/{action_id}/approve "
        "ด้วยบัญชี approver คนละ principal และ action_digest นี้"
    )
    return summary


def create_mcp_server(
    settings: Settings | None = None,
    *,
    principal: Principal | None = None,
):
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError as exc:
        raise RuntimeError("ติดตั้ง MCP ก่อน: pip install 'ntagentshield[mcp]'") from exc

    active_settings = settings or Settings()
    active_principal = principal or _load_mcp_principal(active_settings)
    mcp = FastMCP("NTAgentShield Central")

    @mcp.tool()
    def operator_identity() -> dict[str, object]:
        """แสดง principal, role และ tenant scope ที่ MCP instance นี้ได้รับ"""

        return active_principal.as_safe_dict()

    @mcp.tool()
    def firewall_port_propose(
        tenant_id: str,
        agent_id: str,
        operation: Literal["open", "close"],
        protocol: Literal["TCP", "UDP"],
        direction: Literal["inbound", "outbound"],
        port: int,
        reason: str,
        ttl_seconds: int = 300,
        incident_id: str | None = None,
    ) -> dict[str, Any]:
        """สร้าง typed proposal เท่านั้น ไม่อนุมัติและไม่ส่งคำสั่งไป Agent อัตโนมัติ"""

        store = ResponseBrokerStore(active_settings.database_path)
        try:
            return propose_firewall_port(
                store,
                tenant_id=tenant_id,
                agent_id=agent_id,
                operation=operation,
                protocol=protocol,
                direction=direction,
                port=port,
                reason=reason,
                principal=active_principal,
                ttl_seconds=ttl_seconds,
                incident_id=incident_id,
            )
        finally:
            store.close()

    @mcp.tool()
    def get_response_action(action_id: str) -> dict[str, Any]:
        """อ่านสถานะ proposal โดยบังคับ tenant scope ของ MCP principal"""

        store = ResponseBrokerStore(active_settings.database_path)
        try:
            action = store.get(action_id)
            if action is None:
                raise ValueError("response action not found")
            active_principal.require("read", action.tenant_id)
            return response_action_summary(action)
        finally:
            store.close()

    return mcp


def _load_mcp_principal(settings: Settings) -> Principal:
    del settings  # The token trust root comes from the production security config.
    config = ProductionSecurityConfig.from_env()
    if config.locked:
        raise RuntimeError(
            "MCP security configuration is incomplete: " + "; ".join(config.lock_reasons())
        )
    token = os.getenv("NTSHIELD_MCP_OPERATOR_TOKEN", "").strip()
    if token.startswith("Bearer "):
        token = token[len("Bearer ") :].strip()
    if not token:
        raise RuntimeError("NTSHIELD_MCP_OPERATOR_TOKEN is required")
    manager = OperatorTokenManager(
        config.operator_signing_secret,
        issuer=config.operator_token_issuer,
    )
    principal = manager.verify(token)
    if not principal.has_permission("respond.propose"):
        raise RuntimeError("MCP operator token lacks respond.propose permission")
    return principal


def main() -> None:
    create_mcp_server().run()


if __name__ == "__main__":
    main()
