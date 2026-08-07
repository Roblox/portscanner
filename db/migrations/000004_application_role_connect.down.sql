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

ALTER FUNCTION act.grant_application_role_objects(NAME)
    RENAME TO grant_application_role;
ALTER FUNCTION act.revoke_application_role_objects(NAME)
    RENAME TO revoke_application_role;

REVOKE EXECUTE ON FUNCTION act.grant_application_role(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role(NAME) FROM PUBLIC;

DROP TABLE act.application_role_grants;
DROP TABLE act.database_connect_baseline;

COMMENT ON FUNCTION act.grant_application_role(NAME) IS
    'Owner-invoked, fail-closed grant for an existing runtime role; grants no DDL, DELETE, or rule editing.';
