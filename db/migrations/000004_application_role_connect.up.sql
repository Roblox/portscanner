ALTER FUNCTION act.grant_application_role(NAME)
    RENAME TO grant_application_role_objects;
ALTER FUNCTION act.revoke_application_role(NAME)
    RENAME TO revoke_application_role_objects;

CREATE TABLE act.database_connect_baseline (
    database_name NAME PRIMARY KEY,
    public_connect BOOLEAN NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE act.application_role_grants (
    role_name NAME PRIMARY KEY,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

REVOKE ALL ON TABLE act.database_connect_baseline FROM PUBLIC;
REVOKE ALL ON TABLE act.application_role_grants FROM PUBLIC;

INSERT INTO act.database_connect_baseline (database_name, public_connect)
SELECT
    database.datname,
    EXISTS (
        SELECT 1
        FROM aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba)))
        WHERE grantee = 0
          AND privilege_type = 'CONNECT'
    )
FROM pg_catalog.pg_database AS database
WHERE database.datname = current_database();

DO $$
BEGIN
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', current_database());
END;
$$;

CREATE FUNCTION act.grant_application_role(role_to_grant NAME)
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

CREATE FUNCTION act.revoke_application_role(role_to_revoke NAME)
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

REVOKE EXECUTE ON FUNCTION act.grant_application_role_objects(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.grant_application_role(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role_objects(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role(NAME) FROM PUBLIC;

COMMENT ON FUNCTION act.grant_application_role(NAME) IS
    'Owner-invoked, fail-closed runtime grant with explicit database connectivity and no DDL, DELETE, or rule editing.';
COMMENT ON TABLE act.application_role_grants IS
    'Roles whose direct CONNECT grant is managed by the ACT application-role functions.';
