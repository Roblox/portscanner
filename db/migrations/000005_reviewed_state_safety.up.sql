DROP TRIGGER target_events_append_only ON act.target_events;

ALTER TABLE act.target_events
    ADD COLUMN removed_at TIMESTAMPTZ;

UPDATE act.target_events
SET removed_at = dispatched_at
WHERE event_type = 'remove';

ALTER TABLE act.target_events
    ADD CONSTRAINT target_events_removal_consistent CHECK (
        (event_type = 'upsert' AND removed_at IS NULL)
        OR (event_type = 'remove' AND removed_at IS NOT NULL)
    );

CREATE TRIGGER target_events_append_only
BEFORE UPDATE OR DELETE ON act.target_events
FOR EACH ROW EXECUTE FUNCTION act.reject_append_only_mutation();

ALTER TABLE act.scan_attempts
    ADD COLUMN xml_completion_validated BOOLEAN;

UPDATE act.scan_attempts
SET xml_completion_validated = state_eligible;

ALTER TABLE act.scan_attempts
    ALTER COLUMN xml_completion_validated SET NOT NULL,
    DROP CONSTRAINT scan_attempts_state_eligibility_valid,
    ADD CONSTRAINT scan_attempts_state_eligibility_valid CHECK (
        NOT state_eligible
        OR (
            NOT stale_generation
            AND outcome = 'complete'
            AND xml_completion_validated
        )
    );

CREATE INDEX scan_attempts_state_order_idx
    ON act.scan_attempts (
        target_id,
        generation,
        scan_completed_at DESC,
        attempt_id COLLATE "C" DESC
    )
    WHERE state_eligible;

ALTER TABLE act.exposure_state
    ADD COLUMN last_generation BIGINT;

UPDATE act.exposure_state AS exposure
SET last_generation = attempt.generation
FROM act.scan_attempts AS attempt
WHERE attempt.attempt_id = exposure.last_attempt_id;

ALTER TABLE act.exposure_state
    ALTER COLUMN last_generation SET NOT NULL,
    ADD CONSTRAINT exposure_state_last_generation_positive CHECK (last_generation > 0),
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
    );

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

CREATE OR REPLACE FUNCTION act.grant_application_role(role_to_grant NAME)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM act.grant_application_role_objects(role_to_grant);
    EXECUTE format(
        'GRANT UPDATE (last_generation) ON TABLE act.exposure_state TO %I',
        role_to_grant
    );
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

COMMENT ON TABLE act.application_role_grants IS
    'Roles whose direct CONNECT grant is managed by the ACT application-role functions.';
COMMENT ON FUNCTION act.grant_application_role(NAME) IS
    'Owner-invoked runtime grant with effective dedicated-database CONNECT and no DDL, DELETE, or rule editing.';
