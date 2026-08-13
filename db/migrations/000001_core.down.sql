DO $$
DECLARE
    managed_role NAME;
BEGIN
    FOR managed_role IN
        SELECT role_name FROM act.application_role_grants
    LOOP
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = managed_role) THEN
            EXECUTE format(
                'REVOKE CONNECT ON DATABASE %I FROM %I',
                current_database(),
                managed_role
            );
        END IF;
    END LOOP;
END;
$$;

DO $$
DECLARE
    restore_public_connect BOOLEAN;
BEGIN
    SELECT public_connect
    INTO STRICT restore_public_connect
    FROM act.database_connect_baseline
    WHERE database_name = current_database();

    IF restore_public_connect THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO PUBLIC', current_database());
    ELSE
        EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', current_database());
    END IF;
END;
$$;

DROP FUNCTION act.grant_application_role(NAME);
DROP FUNCTION act.revoke_application_role(NAME);
DROP FUNCTION act.grant_application_role_objects(NAME);
DROP FUNCTION act.revoke_application_role_objects(NAME);

DROP VIEW act.pipeline_latency;
DROP VIEW act.current_findings;
DROP VIEW act.current_exposures;
DROP VIEW act.serving_targets;

DROP TABLE act.application_role_grants;
DROP TABLE act.database_connect_baseline;
DROP TABLE act.finding_handoffs;
DROP TABLE act.reconciliation_runs;
DROP TRIGGER finding_events_append_only ON act.finding_events;
DROP TABLE act.finding_events;
DROP TABLE act.findings;
DROP TABLE act.detection_rules;
DROP TRIGGER exposure_events_append_only ON act.exposure_events;
DROP TABLE act.exposure_events;
DROP TABLE act.exposure_state;
DROP TABLE act.observations;
DROP TABLE act.scan_attempt_coverage;
DROP TABLE act.scan_attempts;
DROP TRIGGER target_events_append_only ON act.target_events;
DROP TABLE act.target_events;
DROP TABLE act.targets;
DROP FUNCTION act.reject_append_only_mutation();
DROP SCHEMA act;
