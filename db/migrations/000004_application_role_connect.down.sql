DROP FUNCTION act.grant_application_role(NAME);
DROP FUNCTION act.revoke_application_role(NAME);

ALTER FUNCTION act.grant_application_role_objects(NAME)
    RENAME TO grant_application_role;
ALTER FUNCTION act.revoke_application_role_objects(NAME)
    RENAME TO revoke_application_role;

REVOKE EXECUTE ON FUNCTION act.grant_application_role(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role(NAME) FROM PUBLIC;

COMMENT ON FUNCTION act.grant_application_role(NAME) IS
    'Owner-invoked, fail-closed grant for an existing runtime role; grants no DDL, DELETE, or rule editing.';
