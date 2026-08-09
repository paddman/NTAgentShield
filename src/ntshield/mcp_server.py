"""MCP tools for Central response orchestration.

These tools create and approve typed Response Broker actions. They never run
shell commands and the proposal and approval steps remain separate so the
Agent can enforce its own signed policy before executing an action.
"""

from __future__ import annotations

from typing import Any, Literal

from ntshield.response_broker import ResponseAction, ResponseBrokerStore
from ntshield.settings import Settings


def build_firewall_port_args(
    operation: str,
    protocol: str,
    direction: str,
    port: int,
) -> dict[str, Any]:
    """Validate and normalize the narrow firewall.port argument schema."""

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
    """Return an MCP-safe, JSON-serializable action summary."""

    return {
        "action_id": action.action_id,
        "tenant_id": action.tenant_id,
        "agent_id": action.agent_id,
        "incident_id": action.incident_id,
        "tool": action.tool,
        "args": action.args,
        "reason": action.reason,
        "risk": action.risk,
        "requested_by": action.requested_by,
        "requested_at": action.requested_at.isoformat(),
        "expires_at": action.expires_at.isoformat(),
        "status": action.status,
        "approved_by": action.approved_by,
        "approved_at": action.approved_at.isoformat() if action.approved_at else None,
        "dispatch_count": action.dispatch_count,
        "completed_at": action.completed_at.isoformat() if action.completed_at else None,
        "result": action.result,
        "requires_approval": action.status == "proposed",
    }


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
    requested_by: str,
    ttl_seconds: int = 300,
    incident_id: str | None = None,
) -> dict[str, Any]:
    args = build_firewall_port_args(operation, protocol, direction, port)
    action = store.create_action(
        tenant_id=tenant_id,
        agent_id=agent_id,
        tool="firewall.port",
        args=args,
        reason=reason,
        requested_by=requested_by,
        ttl_seconds=ttl_seconds,
        incident_id=incident_id,
    )
    summary = response_action_summary(action)
    summary["next_step"] = "เรียก approve_response_action หลังได้รับการอนุมัติจากผู้รับผิดชอบ"
    return summary


def create_mcp_server(settings: Settings | None = None):
    """Create the stdio MCP server used by Central."""

    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError as exc:
        raise RuntimeError("ติดตั้ง MCP ก่อน: pip install 'ntagentshield[mcp]'") from exc

    active_settings = settings or Settings()
    mcp = FastMCP("NTAgentShield Central")

    @mcp.tool()
    def firewall_port_propose(
        tenant_id: str,
        agent_id: str,
        operation: Literal["open", "close"],
        protocol: Literal["TCP", "UDP"],
        direction: Literal["inbound", "outbound"],
        port: int,
        reason: str,
        requested_by: str,
        ttl_seconds: int = 300,
        incident_id: str | None = None,
    ) -> dict[str, Any]:
        """สร้าง proposal เปิด/ปิดพอร์ตแบบ typed; ยังไม่ส่งคำสั่งไป Agent และยังไม่อนุมัติอัตโนมัติ"""

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
                requested_by=requested_by,
                ttl_seconds=ttl_seconds,
                incident_id=incident_id,
            )
        finally:
            store.close()

    @mcp.tool()
    def approve_response_action(action_id: str, approved_by: str) -> dict[str, Any]:
        """อนุมัติ proposal ที่ตรวจสอบแล้ว; ใช้แยกจากการสร้าง proposal เสมอ"""

        store = ResponseBrokerStore(active_settings.database_path)
        try:
            return response_action_summary(store.approve(action_id, approved_by))
        finally:
            store.close()

    @mcp.tool()
    def get_response_action(action_id: str) -> dict[str, Any]:
        """ตรวจสถานะ proposal, การ dispatch และผลลัพธ์ของ Agent"""

        store = ResponseBrokerStore(active_settings.database_path)
        try:
            action = store.get(action_id)
            if action is None:
                raise ValueError("response action not found")
            return response_action_summary(action)
        finally:
            store.close()

    return mcp


def main() -> None:
    create_mcp_server().run()


if __name__ == "__main__":
    main()
