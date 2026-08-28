from __future__ import annotations

import pytest

from ntshield.operator_auth import AuthenticationError, OperatorTokenManager

SECRET = "operator-secret-0123456789-abcdefghijklmnopqrstuvwxyz"


def test_operator_token_is_signed_tenant_bound_and_tamper_evident() -> None:
    manager = OperatorTokenManager(SECRET, issuer="test-control")
    token = manager.issue(
        subject="alice@example.com",
        roles=["analyst", "responder"],
        tenant_ids=["tenant-a"],
        ttl_seconds=600,
        now=1_000,
        token_id="token-1",
    )
    principal = manager.verify(token, now=1_100)
    assert principal.subject == "alice@example.com"
    assert principal.can_access_tenant("tenant-a")
    assert not principal.can_access_tenant("tenant-b")
    assert principal.has_permission("respond.propose")
    assert not principal.has_permission("respond.approve")

    prefix, payload, signature = token.split(".")
    tampered = f"{prefix}.{payload[:-1]}A.{signature}"
    with pytest.raises(AuthenticationError):
        manager.verify(tampered, now=1_100)


def test_operator_token_expiry_and_role_validation() -> None:
    manager = OperatorTokenManager(SECRET)
    token = manager.issue(
        subject="auditor",
        roles=["auditor"],
        tenant_ids=["tenant-a"],
        ttl_seconds=60,
        now=100,
    )
    with pytest.raises(AuthenticationError, match="expired"):
        manager.verify(token, now=200, clock_skew_seconds=0)
    with pytest.raises(ValueError, match="unknown operator roles"):
        manager.issue(
            subject="mallory",
            roles=["totally-admin"],
            tenant_ids=["tenant-a"],
            ttl_seconds=60,
            now=100,
        )


def test_platform_admin_may_use_wildcard_but_tenant_operator_may_not() -> None:
    manager = OperatorTokenManager(SECRET)
    platform = manager.issue(
        subject="platform-admin",
        roles=["platform_admin"],
        tenant_ids=[],
        ttl_seconds=60,
        now=100,
    )
    assert manager.verify(platform, now=110).can_access_tenant("any-tenant")

    with pytest.raises(ValueError, match="wildcard tenant"):
        manager.issue(
            subject="tenant-admin",
            roles=["tenant_admin"],
            tenant_ids=["*"],
            ttl_seconds=60,
            now=100,
        )
