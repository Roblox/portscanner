CREATE VIEW act.serving_targets AS
SELECT
    target_id,
    provider,
    provider_scope_id,
    provider_target_id,
    location,
    current_generation,
    current_addresses,
    context,
    source_observed_at,
    last_attempt_at,
    last_confirmed_at,
    created_at,
    updated_at
FROM act.targets
WHERE status = 'active';

CREATE VIEW act.current_exposures AS
SELECT
    exposure.target_id,
    target.provider,
    target.provider_scope_id,
    target.provider_target_id,
    target.location,
    target.current_generation,
    exposure.protocol,
    exposure.port,
    exposure.observed_address,
    exposure.service_name,
    exposure.service_product,
    exposure.service_version,
    exposure.certificate_sha256,
    exposure.ssh_host_key_sha256,
    exposure.banner_sha256,
    exposure.service_identity_sha256,
    exposure.first_opened_at,
    exposure.last_confirmed_at,
    exposure.last_changed_at,
    exposure.state_version,
    exposure.last_attempt_id
FROM act.exposure_state AS exposure
JOIN act.targets AS target USING (target_id)
WHERE exposure.state = 'open'
  AND target.status = 'active';

CREATE VIEW act.current_findings AS
SELECT
    finding.fingerprint,
    finding.target_id,
    target.provider,
    target.provider_scope_id,
    target.provider_target_id,
    target.location,
    target.current_generation,
    finding.protocol,
    finding.port,
    finding.rule_key,
    finding.severity,
    finding.title,
    finding.description,
    finding.observed_address,
    finding.service_name,
    finding.service_product,
    finding.service_version,
    finding.certificate_sha256,
    finding.ssh_host_key_sha256,
    finding.banner_sha256,
    finding.service_identity_sha256,
    finding.first_opened_at,
    finding.last_seen_at,
    finding.last_changed_at,
    finding.finding_version,
    finding.last_event_key
FROM act.findings AS finding
JOIN act.targets AS target USING (target_id)
WHERE finding.status = 'open'
  AND target.status = 'active';

CREATE VIEW act.pipeline_latency AS
WITH first_finding AS (
    SELECT
        source_attempt_id,
        min(recorded_at) AS first_finding_recorded_at
    FROM act.finding_events
    WHERE source_attempt_id IS NOT NULL
    GROUP BY source_attempt_id
),
first_handoff AS (
    SELECT
        source_attempt_id,
        min(published_at) AS first_handoff_published_at
    FROM act.finding_handoffs
    WHERE source_attempt_id IS NOT NULL
      AND published_at IS NOT NULL
    GROUP BY source_attempt_id
)
SELECT
    attempt.attempt_id,
    attempt.result_id,
    attempt.run_id,
    attempt.directive_id,
    attempt.target_event_id,
    attempt.trace_id,
    attempt.target_id,
    attempt.generation,
    attempt.outcome,
    attempt.stale_generation,
    attempt.state_eligible,
    attempt.source_observed_at,
    attempt.dispatched_at,
    attempt.scan_started_at,
    attempt.scan_completed_at,
    attempt.result_uploaded_at,
    attempt.ingested_at,
    first_finding.first_finding_recorded_at,
    first_handoff.first_handoff_published_at,
    round(
        extract(epoch FROM (attempt.dispatched_at - attempt.source_observed_at)) * 1000
    )::BIGINT AS dispatch_latency_ms,
    round(
        extract(epoch FROM (attempt.scan_completed_at - attempt.scan_started_at)) * 1000
    )::BIGINT AS scan_latency_ms,
    round(
        extract(epoch FROM (attempt.ingested_at - attempt.scan_completed_at)) * 1000
    )::BIGINT AS ingestion_latency_ms,
    CASE
        WHEN first_finding.first_finding_recorded_at IS NULL THEN NULL
        ELSE round(
            extract(
                epoch FROM (
                    first_finding.first_finding_recorded_at - attempt.source_observed_at
                )
            ) * 1000
        )::BIGINT
    END AS finding_latency_ms,
    CASE
        WHEN first_handoff.first_handoff_published_at IS NULL THEN NULL
        ELSE round(
            extract(
                epoch FROM (
                    first_handoff.first_handoff_published_at - attempt.source_observed_at
                )
            ) * 1000
        )::BIGINT
    END AS handoff_latency_ms
FROM act.scan_attempts AS attempt
LEFT JOIN first_finding
    ON first_finding.source_attempt_id = attempt.attempt_id
LEFT JOIN first_handoff
    ON first_handoff.source_attempt_id = attempt.attempt_id;

COMMENT ON VIEW act.current_exposures IS
    'Serving view of open services on active targets, keyed by target_id, protocol, and port.';
COMMENT ON VIEW act.current_findings IS
    'Serving view containing only unresolved findings on active targets.';
COMMENT ON VIEW act.pipeline_latency IS
    'End-to-end event, scan, ingestion, finding, and handoff timestamps and latency.';

CREATE FUNCTION act.grant_application_role(role_to_grant NAME)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_to_grant) THEN
        RAISE EXCEPTION 'application role % does not exist', role_to_grant
            USING ERRCODE = '42704';
    END IF;

    EXECUTE format('GRANT USAGE ON SCHEMA act TO %I', role_to_grant);
    EXECUTE format(
        'GRANT SELECT ON TABLE '
        'act.detection_rules, act.serving_targets, act.current_exposures, '
        'act.current_findings, act.pipeline_latency TO %I',
        role_to_grant
    );
    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE '
        'act.targets, act.exposure_state, act.findings, '
        'act.finding_handoffs, act.reconciliation_runs TO %I',
        role_to_grant
    );
    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE '
        'act.target_events, act.scan_attempts, act.scan_attempt_coverage, '
        'act.observations, act.exposure_events, act.finding_events TO %I',
        role_to_grant
    );
    EXECUTE format(
        'GRANT UPDATE ('
        'location, current_generation, status, current_addresses, context, '
        'source_observed_at, last_attempt_at, last_confirmed_at, updated_at, removed_at'
        ') ON TABLE act.targets TO %I',
        role_to_grant
    );
    EXECUTE format(
        'GRANT UPDATE ('
        'state, observed_address, service_name, service_product, service_version, '
        'certificate_sha256, ssh_host_key_sha256, banner_sha256, '
        'service_identity_sha256, last_confirmed_at, last_changed_at, closed_at, '
        'closure_reason, last_attempt_id, state_version'
        ') ON TABLE act.exposure_state TO %I',
        role_to_grant
    );
    EXECUTE format(
        'GRANT UPDATE ('
        'status, severity, title, description, observed_address, service_name, '
        'service_product, service_version, certificate_sha256, ssh_host_key_sha256, '
        'banner_sha256, service_identity_sha256, last_seen_at, last_changed_at, '
        'resolved_at, resolution_reason, finding_version, last_event_key'
        ') ON TABLE act.findings TO %I',
        role_to_grant
    );
    EXECUTE format(
        'GRANT UPDATE ('
        'first_attempted_at, last_attempted_at, published_at, '
        'publish_attempts, last_error_code'
        ') ON TABLE act.finding_handoffs TO %I',
        role_to_grant
    );
    EXECUTE format(
        'GRANT UPDATE (completed_at, findings_examined, handoffs_queued) '
        'ON TABLE act.reconciliation_runs TO %I',
        role_to_grant
    );
    EXECUTE format(
        'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA act TO %I',
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
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_to_revoke) THEN
        RETURN;
    END IF;

    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA act FROM %I',
        role_to_revoke
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA act FROM %I',
        role_to_revoke
    );
    EXECUTE format('REVOKE USAGE ON SCHEMA act FROM %I', role_to_revoke);
END;
$$;

REVOKE ALL ON SCHEMA act FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA act FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA act FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.reject_append_only_mutation() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.grant_application_role(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role(NAME) FROM PUBLIC;

COMMENT ON FUNCTION act.grant_application_role(NAME) IS
    'Owner-invoked, fail-closed grant for an existing runtime role; grants no DDL, DELETE, or rule editing.';
