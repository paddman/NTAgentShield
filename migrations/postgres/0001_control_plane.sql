CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(128) PRIMARY KEY,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    retention_days INTEGER NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 3650),
    event_quota_per_day BIGINT NOT NULL DEFAULT 1000000 CHECK (event_quota_per_day > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operator_identities (
    subject VARCHAR(128) PRIMARY KEY,
    display_name VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS operator_tenant_roles (
    subject VARCHAR(128) NOT NULL REFERENCES operator_identities(subject) ON DELETE CASCADE,
    tenant_id VARCHAR(128) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    role VARCHAR(64) NOT NULL,
    granted_by VARCHAR(128) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (subject, tenant_id, role)
);

CREATE TABLE IF NOT EXISTS security_cases (
    case_id UUID PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    title VARCHAR(512) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    owner_subject VARCHAR(128),
    incident_id VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_security_cases_tenant_updated
    ON security_cases(tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS case_timeline (
    timeline_id BIGSERIAL PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES security_cases(case_id) ON DELETE CASCADE,
    tenant_id VARCHAR(128) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    event_type VARCHAR(128) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_case_timeline_case_time
    ON case_timeline(case_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_anchors (
    anchor_id BIGSERIAL PRIMARY KEY,
    ledger_sequence BIGINT NOT NULL UNIQUE,
    ledger_hash CHAR(64) NOT NULL,
    storage_uri TEXT,
    anchored_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
