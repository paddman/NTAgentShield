ALTER TABLE security_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_timeline ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS security_cases_tenant_policy ON security_cases;
CREATE POLICY security_cases_tenant_policy ON security_cases
    USING (
        current_setting('ntshield.platform_admin', true) = 'true'
        OR tenant_id = current_setting('ntshield.tenant_id', true)
    )
    WITH CHECK (
        current_setting('ntshield.platform_admin', true) = 'true'
        OR tenant_id = current_setting('ntshield.tenant_id', true)
    );

DROP POLICY IF EXISTS case_timeline_tenant_policy ON case_timeline;
CREATE POLICY case_timeline_tenant_policy ON case_timeline
    USING (
        current_setting('ntshield.platform_admin', true) = 'true'
        OR tenant_id = current_setting('ntshield.tenant_id', true)
    )
    WITH CHECK (
        current_setting('ntshield.platform_admin', true) = 'true'
        OR tenant_id = current_setting('ntshield.tenant_id', true)
    );
