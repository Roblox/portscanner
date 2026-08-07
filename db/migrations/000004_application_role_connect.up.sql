ALTER FUNCTION act.grant_application_role(NAME)
    RENAME TO grant_application_role_objects;
ALTER FUNCTION act.revoke_application_role(NAME)
    RENAME TO revoke_application_role_objects;

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
END;
$$;

REVOKE EXECUTE ON FUNCTION act.grant_application_role_objects(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.grant_application_role(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role_objects(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role(NAME) FROM PUBLIC;

COMMENT ON FUNCTION act.grant_application_role(NAME) IS
    'Owner-invoked, fail-closed runtime grant with explicit database connectivity and no DDL, DELETE, or rule editing.';
