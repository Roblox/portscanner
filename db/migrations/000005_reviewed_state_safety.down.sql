CREATE OR REPLACE FUNCTION act.grant_application_role(role_to_grant NAME)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM act.grant_application_role_objects(role_to_grant);
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO %I',
        current_database(),
        role_to_grant
    );
    INSERT INTO act.application_role_grants (role_name)
    VALUES (role_to_grant)
    ON CONFLICT (role_name) DO UPDATE
    SET granted_at = clock_timestamp();
END;
$$;

CREATE OR REPLACE FUNCTION act.revoke_application_role(role_to_revoke NAME)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM act.revoke_application_role_objects(role_to_revoke);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_to_revoke) THEN
        EXECUTE format(
            'REVOKE CONNECT ON DATABASE %I FROM %I',
            current_database(),
            role_to_revoke
        );
    END IF;
    DELETE FROM act.application_role_grants WHERE role_name = role_to_revoke;
END;
$$;

REVOKE EXECUTE ON FUNCTION act.grant_application_role(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role(NAME) FROM PUBLIC;

ALTER TABLE act.exposure_events
    DROP CONSTRAINT exposure_events_reason_valid,
    ADD CONSTRAINT exposure_events_reason_valid CHECK (
        reason IN (
            'open_observation',
            'service_changed',
            'address_changed',
            'explicit_closed',
            'explicit_filtered',
            'coverage_absence',
            'ownership_removed',
            'address_binding_changed',
            'generation_gap_reactivation'
        )
    );

ALTER TABLE act.exposure_state
    DROP CONSTRAINT exposure_state_closure_valid,
    ADD CONSTRAINT exposure_state_closure_valid CHECK (
        (state = 'open' AND closed_at IS NULL AND closure_reason IS NULL)
        OR (
            state = 'closed'
            AND closed_at IS NOT NULL
            AND closure_reason IN (
                'explicit_closed',
                'explicit_filtered',
                'coverage_absence',
                'ownership_removed',
                'address_binding_changed',
                'generation_gap_reactivation'
            )
        )
    ),
    DROP CONSTRAINT exposure_state_last_generation_positive,
    DROP COLUMN last_generation;

DROP INDEX act.scan_attempts_state_order_idx;

ALTER TABLE act.scan_attempts
    DROP CONSTRAINT scan_attempts_state_eligibility_valid,
    ADD CONSTRAINT scan_attempts_state_eligibility_valid CHECK (
        NOT state_eligible
        OR (NOT stale_generation AND outcome = 'complete')
    ),
    DROP COLUMN xml_completion_validated;

DROP TRIGGER target_events_append_only ON act.target_events;

ALTER TABLE act.target_events
    DROP CONSTRAINT target_events_removal_consistent,
    DROP COLUMN removed_at;

CREATE TRIGGER target_events_append_only
BEFORE UPDATE OR DELETE ON act.target_events
FOR EACH ROW EXECUTE FUNCTION act.reject_append_only_mutation();

COMMENT ON FUNCTION act.grant_application_role(NAME) IS
    'Owner-invoked, fail-closed runtime grant with explicit database connectivity and no DDL, DELETE, or rule editing.';
