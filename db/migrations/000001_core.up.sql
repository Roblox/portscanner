CREATE SCHEMA act;

COMMENT ON SCHEMA act IS
    'ACT data plane. Objects are owned by the migration role; runtime access is granted explicitly.';

CREATE FUNCTION act.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE TABLE act.targets (
    target_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_scope_id TEXT NOT NULL,
    provider_target_id TEXT NOT NULL,
    location TEXT,
    current_generation BIGINT NOT NULL,
    status TEXT NOT NULL,
    current_addresses INET[] NOT NULL DEFAULT ARRAY[]::INET[],
    context JSONB NOT NULL DEFAULT '{}'::JSONB,
    source_observed_at TIMESTAMPTZ NOT NULL,
    last_attempt_at TIMESTAMPTZ,
    last_confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    removed_at TIMESTAMPTZ,
    CONSTRAINT targets_target_id_nonempty CHECK (btrim(target_id) <> ''),
    CONSTRAINT targets_provider_nonempty CHECK (btrim(provider) <> ''),
    CONSTRAINT targets_provider_scope_id_nonempty CHECK (btrim(provider_scope_id) <> ''),
    CONSTRAINT targets_provider_target_id_nonempty CHECK (btrim(provider_target_id) <> ''),
    CONSTRAINT targets_generation_positive CHECK (current_generation > 0),
    CONSTRAINT targets_status_valid CHECK (status IN ('active', 'removed')),
    CONSTRAINT targets_context_object CHECK (jsonb_typeof(context) = 'object'),
    CONSTRAINT targets_removal_consistent CHECK (
        (status = 'active' AND removed_at IS NULL)
        OR (status = 'removed' AND removed_at IS NOT NULL)
    ),
    CONSTRAINT targets_provider_identity_unique
        UNIQUE (provider, provider_scope_id, provider_target_id)
);

CREATE INDEX targets_active_generation_idx
    ON act.targets (target_id, current_generation)
    WHERE status = 'active';

CREATE TABLE act.target_events (
    event_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES act.targets (target_id),
    generation BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_scope_id TEXT NOT NULL,
    provider_target_id TEXT NOT NULL,
    location TEXT,
    addresses INET[] NOT NULL DEFAULT ARRAY[]::INET[],
    context JSONB NOT NULL DEFAULT '{}'::JSONB,
    source_event_time TIMESTAMPTZ NOT NULL,
    source_observed_at TIMESTAMPTZ NOT NULL,
    source_collected_at TIMESTAMPTZ NOT NULL,
    dispatched_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    accepted BOOLEAN NOT NULL,
    stale BOOLEAN NOT NULL,
    removed_at TIMESTAMPTZ,
    CONSTRAINT target_events_event_id_nonempty CHECK (btrim(event_id) <> ''),
    CONSTRAINT target_events_generation_positive CHECK (generation > 0),
    CONSTRAINT target_events_type_valid CHECK (event_type IN ('upsert', 'remove')),
    CONSTRAINT target_events_provider_nonempty CHECK (btrim(provider) <> ''),
    CONSTRAINT target_events_provider_scope_id_nonempty CHECK (btrim(provider_scope_id) <> ''),
    CONSTRAINT target_events_provider_target_id_nonempty CHECK (btrim(provider_target_id) <> ''),
    CONSTRAINT target_events_context_object CHECK (jsonb_typeof(context) = 'object'),
    CONSTRAINT target_events_timeline_valid CHECK (
        source_event_time <= source_observed_at
        AND source_observed_at <= source_collected_at
        AND source_collected_at <= dispatched_at
    ),
    CONSTRAINT target_events_disposition_valid CHECK (NOT (accepted AND stale)),
    CONSTRAINT target_events_removal_consistent CHECK (
        (event_type = 'upsert' AND removed_at IS NULL)
        OR (event_type = 'remove' AND removed_at IS NOT NULL)
    )
);

CREATE INDEX target_events_target_generation_idx
    ON act.target_events (target_id, generation, received_at);

CREATE TRIGGER target_events_append_only
BEFORE UPDATE OR DELETE ON act.target_events
FOR EACH ROW EXECUTE FUNCTION act.reject_append_only_mutation();

CREATE TABLE act.scan_attempts (
    attempt_id TEXT PRIMARY KEY,
    result_id CHAR(64) NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    directive_id TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES act.targets (target_id),
    target_event_id TEXT NOT NULL REFERENCES act.target_events (event_id),
    trace_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    provider TEXT NOT NULL,
    observed_address INET NOT NULL,
    profile TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    outcome TEXT NOT NULL,
    exit_code INTEGER,
    error_type TEXT,
    error_retryable BOOLEAN,
    source_event_time TIMESTAMPTZ NOT NULL,
    source_observed_at TIMESTAMPTZ NOT NULL,
    source_collected_at TIMESTAMPTZ NOT NULL,
    dispatched_at TIMESTAMPTZ NOT NULL,
    scan_started_at TIMESTAMPTZ NOT NULL,
    scan_completed_at TIMESTAMPTZ NOT NULL,
    result_uploaded_at TIMESTAMPTZ,
    source_envelope_bucket TEXT NOT NULL,
    source_envelope_key TEXT NOT NULL,
    source_envelope_version TEXT,
    source_envelope_sha256 CHAR(64) NOT NULL,
    raw_result_bucket TEXT,
    raw_result_key TEXT,
    raw_result_version TEXT,
    raw_result_sha256 CHAR(64),
    enrichment_result_bucket TEXT,
    enrichment_result_key TEXT,
    enrichment_result_version TEXT,
    enrichment_result_sha256 CHAR(64),
    stale_generation BOOLEAN NOT NULL,
    state_eligible BOOLEAN NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    xml_completion_validated BOOLEAN NOT NULL,
    CONSTRAINT scan_attempts_attempt_id_nonempty CHECK (btrim(attempt_id) <> ''),
    CONSTRAINT scan_attempts_result_id_valid CHECK (result_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT scan_attempts_run_id_nonempty CHECK (btrim(run_id) <> ''),
    CONSTRAINT scan_attempts_directive_id_nonempty CHECK (btrim(directive_id) <> ''),
    CONSTRAINT scan_attempts_target_event_id_nonempty CHECK (btrim(target_event_id) <> ''),
    CONSTRAINT scan_attempts_trace_id_nonempty CHECK (btrim(trace_id) <> ''),
    CONSTRAINT scan_attempts_generation_positive CHECK (generation > 0),
    CONSTRAINT scan_attempts_provider_nonempty CHECK (btrim(provider) <> ''),
    CONSTRAINT scan_attempts_profile_nonempty CHECK (btrim(profile) <> ''),
    CONSTRAINT scan_attempts_scanner_version_nonempty CHECK (btrim(scanner_version) <> ''),
    CONSTRAINT scan_attempts_outcome_valid CHECK (
        outcome IN (
            'complete',
            'partial',
            'failed',
            'cancelled',
            'freshness_rejected',
            'timeout'
        )
    ),
    CONSTRAINT scan_attempts_time_order CHECK (scan_completed_at >= scan_started_at),
    CONSTRAINT scan_attempts_envelope_hash_valid CHECK (
        source_envelope_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT scan_attempts_raw_reference_complete CHECK (
        (
            raw_result_bucket IS NULL
            AND raw_result_key IS NULL
            AND raw_result_version IS NULL
            AND raw_result_sha256 IS NULL
        )
        OR (
            raw_result_bucket IS NOT NULL
            AND btrim(raw_result_bucket) <> ''
            AND raw_result_key IS NOT NULL
            AND btrim(raw_result_key) <> ''
            AND raw_result_sha256 ~ '^[0-9a-f]{64}$'
        )
    ),
    CONSTRAINT scan_attempts_enrichment_reference_complete CHECK (
        (
            enrichment_result_bucket IS NULL
            AND enrichment_result_key IS NULL
            AND enrichment_result_version IS NULL
            AND enrichment_result_sha256 IS NULL
        )
        OR (
            raw_result_bucket IS NOT NULL
            AND enrichment_result_bucket IS NOT NULL
            AND btrim(enrichment_result_bucket) <> ''
            AND enrichment_result_key IS NOT NULL
            AND btrim(enrichment_result_key) <> ''
            AND enrichment_result_sha256 ~ '^[0-9a-f]{64}$'
        )
    ),
    CONSTRAINT scan_attempts_error_complete CHECK (
        (error_type IS NULL AND error_retryable IS NULL)
        OR (error_type IS NOT NULL AND error_retryable IS NOT NULL)
    ),
    CONSTRAINT scan_attempts_state_eligibility_valid CHECK (
        NOT state_eligible
        OR (
            NOT stale_generation
            AND outcome = 'complete'
            AND xml_completion_validated
        )
    )
);

CREATE INDEX scan_attempts_target_generation_idx
    ON act.scan_attempts (target_id, generation, ingested_at DESC);

CREATE INDEX scan_attempts_pending_latency_idx
    ON act.scan_attempts (ingested_at DESC, source_observed_at);

CREATE INDEX scan_attempts_state_order_idx
    ON act.scan_attempts (
        target_id,
        generation,
        scan_completed_at DESC,
        attempt_id COLLATE "C" DESC
    )
    WHERE state_eligible;

CREATE TABLE act.scan_attempt_coverage (
    attempt_id TEXT NOT NULL REFERENCES act.scan_attempts (attempt_id) ON DELETE RESTRICT,
    protocol TEXT NOT NULL,
    port_spec TEXT NOT NULL,
    port_from INTEGER,
    port_to INTEGER,
    complete BOOLEAN NOT NULL,
    PRIMARY KEY (attempt_id, protocol, port_spec),
    CONSTRAINT scan_attempt_coverage_protocol_valid CHECK (
        protocol ~ '^[a-z][a-z0-9_-]{0,15}$'
    ),
    CONSTRAINT scan_attempt_coverage_spec_nonempty CHECK (btrim(port_spec) <> ''),
    CONSTRAINT scan_attempt_coverage_bounds_valid CHECK (
        (port_from IS NULL AND port_to IS NULL)
        OR (
            port_from BETWEEN 1 AND 65535
            AND port_to BETWEEN port_from AND 65535
        )
    )
);

CREATE INDEX scan_attempt_coverage_ranges_idx
    ON act.scan_attempt_coverage (attempt_id, protocol, port_from, port_to)
    WHERE complete AND port_from IS NOT NULL;

CREATE TABLE act.observations (
    observation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES act.scan_attempts (attempt_id) ON DELETE RESTRICT,
    target_id TEXT NOT NULL REFERENCES act.targets (target_id),
    generation BIGINT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    observed_address INET NOT NULL,
    state TEXT NOT NULL,
    service_name TEXT,
    service_product TEXT,
    service_version TEXT,
    certificate_sha256 CHAR(64),
    ssh_host_key_sha256 CHAR(64),
    banner_sha256 CHAR(64),
    service_identity_sha256 CHAR(64) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT observations_generation_positive CHECK (generation > 0),
    CONSTRAINT observations_protocol_valid CHECK (
        protocol ~ '^[a-z][a-z0-9_-]{0,15}$'
    ),
    CONSTRAINT observations_port_valid CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT observations_state_valid CHECK (
        state IN ('open', 'closed', 'filtered', 'unknown')
    ),
    CONSTRAINT observations_service_name_size CHECK (
        service_name IS NULL OR char_length(service_name) <= 255
    ),
    CONSTRAINT observations_service_product_size CHECK (
        service_product IS NULL OR char_length(service_product) <= 255
    ),
    CONSTRAINT observations_service_version_size CHECK (
        service_version IS NULL OR char_length(service_version) <= 255
    ),
    CONSTRAINT observations_certificate_hash_valid CHECK (
        certificate_sha256 IS NULL OR certificate_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT observations_ssh_hash_valid CHECK (
        ssh_host_key_sha256 IS NULL OR ssh_host_key_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT observations_banner_hash_valid CHECK (
        banner_sha256 IS NULL OR banner_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT observations_identity_hash_valid CHECK (
        service_identity_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT observations_attempt_service_unique
        UNIQUE (attempt_id, target_id, protocol, port)
);

CREATE INDEX observations_target_service_idx
    ON act.observations (target_id, protocol, port, observed_at DESC);

CREATE TABLE act.exposure_state (
    target_id TEXT NOT NULL REFERENCES act.targets (target_id),
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    observed_address INET NOT NULL,
    service_name TEXT,
    service_product TEXT,
    service_version TEXT,
    certificate_sha256 CHAR(64),
    ssh_host_key_sha256 CHAR(64),
    banner_sha256 CHAR(64),
    service_identity_sha256 CHAR(64) NOT NULL,
    first_opened_at TIMESTAMPTZ NOT NULL,
    last_confirmed_at TIMESTAMPTZ NOT NULL,
    last_changed_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,
    closure_reason TEXT,
    last_attempt_id TEXT NOT NULL REFERENCES act.scan_attempts (attempt_id),
    state_version BIGINT NOT NULL DEFAULT 1,
    last_generation BIGINT NOT NULL,
    PRIMARY KEY (target_id, protocol, port),
    CONSTRAINT exposure_state_protocol_valid CHECK (
        protocol ~ '^[a-z][a-z0-9_-]{0,15}$'
    ),
    CONSTRAINT exposure_state_port_valid CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT exposure_state_state_valid CHECK (state IN ('open', 'closed')),
    CONSTRAINT exposure_state_identity_hash_valid CHECK (
        service_identity_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT exposure_state_version_positive CHECK (state_version > 0),
    CONSTRAINT exposure_state_last_generation_positive CHECK (last_generation > 0),
    CONSTRAINT exposure_state_closure_valid CHECK (
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
    )
);

CREATE INDEX exposure_state_open_idx
    ON act.exposure_state (target_id, protocol, port)
    WHERE state = 'open';

CREATE TABLE act.exposure_events (
    event_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    event_key CHAR(64) PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES act.targets (target_id),
    generation BIGINT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    source_attempt_id TEXT REFERENCES act.scan_attempts (attempt_id),
    event_type TEXT NOT NULL,
    previous_state TEXT,
    new_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    previous_service_identity_sha256 CHAR(64),
    service_identity_sha256 CHAR(64) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT exposure_events_key_valid CHECK (event_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT exposure_events_generation_positive CHECK (generation > 0),
    CONSTRAINT exposure_events_protocol_valid CHECK (
        protocol ~ '^[a-z][a-z0-9_-]{0,15}$'
    ),
    CONSTRAINT exposure_events_port_valid CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT exposure_events_type_valid CHECK (
        event_type IN ('opened', 'reopened', 'updated', 'closed')
    ),
    CONSTRAINT exposure_events_previous_state_valid CHECK (
        previous_state IS NULL OR previous_state IN ('open', 'closed')
    ),
    CONSTRAINT exposure_events_new_state_valid CHECK (new_state IN ('open', 'closed')),
    CONSTRAINT exposure_events_reason_valid CHECK (
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
    ),
    CONSTRAINT exposure_events_previous_hash_valid CHECK (
        previous_service_identity_sha256 IS NULL
        OR previous_service_identity_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT exposure_events_hash_valid CHECK (
        service_identity_sha256 ~ '^[0-9a-f]{64}$'
    )
);

CREATE INDEX exposure_events_target_service_idx
    ON act.exposure_events (target_id, protocol, port, event_sequence DESC);

CREATE INDEX exposure_events_attempt_idx
    ON act.exposure_events (source_attempt_id)
    WHERE source_attempt_id IS NOT NULL;

CREATE TRIGGER exposure_events_append_only
BEFORE UPDATE OR DELETE ON act.exposure_events
FOR EACH ROW EXECUTE FUNCTION act.reject_append_only_mutation();

CREATE TABLE act.detection_rules (
    rule_key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    severity TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    match_criteria JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT detection_rules_key_nonempty CHECK (btrim(rule_key) <> ''),
    CONSTRAINT detection_rules_name_nonempty CHECK (btrim(name) <> ''),
    CONSTRAINT detection_rules_description_nonempty CHECK (btrim(description) <> ''),
    CONSTRAINT detection_rules_severity_valid CHECK (
        severity IN ('informational', 'low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT detection_rules_type_valid CHECK (
        rule_type IN ('exposure', 'port')
    ),
    CONSTRAINT detection_rules_criteria_object CHECK (
        jsonb_typeof(match_criteria) = 'object'
    )
);

COMMENT ON COLUMN act.detection_rules.match_criteria IS
    'Editable generic predicate. exposure rules use protocols; port rules use protocols and ports.';

INSERT INTO act.detection_rules (
    rule_key,
    name,
    description,
    severity,
    rule_type,
    match_criteria
)
VALUES
    (
        'new-or-reopened-exposure',
        'New or reopened network exposure',
        'A network service is currently reachable and was newly observed or reopened.',
        'low',
        'exposure',
        '{"protocols":["tcp","udp"]}'::JSONB
    ),
    (
        'common-public-management-port',
        'Common public management port',
        'A commonly used remote administration or management port is currently reachable.',
        'high',
        'port',
        '{"protocols":["tcp"],"ports":[22,23,2375,2376,3389,5900,5985,5986,6443]}'::JSONB
    ),
    (
        'common-public-database-port',
        'Common public database port',
        'A commonly used database or data service port is currently reachable.',
        'high',
        'port',
        '{"protocols":["tcp"],"ports":[1433,1521,3306,5432,6379,9042,9200,27017]}'::JSONB
    );

CREATE TABLE act.findings (
    fingerprint CHAR(64) PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES act.targets (target_id),
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    rule_key TEXT NOT NULL REFERENCES act.detection_rules (rule_key) ON UPDATE CASCADE,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    observed_address INET NOT NULL,
    service_name TEXT,
    service_product TEXT,
    service_version TEXT,
    certificate_sha256 CHAR(64),
    ssh_host_key_sha256 CHAR(64),
    banner_sha256 CHAR(64),
    service_identity_sha256 CHAR(64) NOT NULL,
    first_opened_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_changed_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    resolution_reason TEXT,
    finding_version BIGINT NOT NULL DEFAULT 1,
    last_event_key CHAR(64) NOT NULL,
    CONSTRAINT findings_fingerprint_valid CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT findings_protocol_valid CHECK (
        protocol ~ '^[a-z][a-z0-9_-]{0,15}$'
    ),
    CONSTRAINT findings_port_valid CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT findings_status_valid CHECK (status IN ('open', 'resolved')),
    CONSTRAINT findings_severity_valid CHECK (
        severity IN ('informational', 'low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT findings_title_nonempty CHECK (btrim(title) <> ''),
    CONSTRAINT findings_description_nonempty CHECK (btrim(description) <> ''),
    CONSTRAINT findings_identity_hash_valid CHECK (
        service_identity_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT findings_version_positive CHECK (finding_version > 0),
    CONSTRAINT findings_last_event_key_valid CHECK (last_event_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT findings_resolution_valid CHECK (
        (status = 'open' AND resolved_at IS NULL AND resolution_reason IS NULL)
        OR (
            status = 'resolved'
            AND resolved_at IS NOT NULL
            AND resolution_reason IN (
                'exposure_closed',
                'ownership_removed',
                'rule_disabled',
                'rule_no_longer_matches'
            )
        )
    ),
    CONSTRAINT findings_rule_service_unique
        UNIQUE (target_id, protocol, port, rule_key)
);

CREATE INDEX findings_open_target_idx
    ON act.findings (target_id, protocol, port)
    WHERE status = 'open';

CREATE INDEX findings_rule_status_idx
    ON act.findings (rule_key, status);

CREATE TABLE act.finding_events (
    event_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    event_key CHAR(64) PRIMARY KEY,
    fingerprint CHAR(64) NOT NULL REFERENCES act.findings (fingerprint),
    target_id TEXT NOT NULL REFERENCES act.targets (target_id),
    target_generation BIGINT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    rule_key TEXT NOT NULL REFERENCES act.detection_rules (rule_key) ON UPDATE CASCADE,
    event_type TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    finding_version BIGINT NOT NULL,
    source_kind TEXT NOT NULL,
    source_key TEXT NOT NULL,
    source_attempt_id TEXT REFERENCES act.scan_attempts (attempt_id),
    service_identity_sha256 CHAR(64) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT finding_events_key_valid CHECK (event_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT finding_events_generation_positive CHECK (target_generation > 0),
    CONSTRAINT finding_events_protocol_valid CHECK (
        protocol ~ '^[a-z][a-z0-9_-]{0,15}$'
    ),
    CONSTRAINT finding_events_port_valid CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT finding_events_type_valid CHECK (
        event_type IN ('opened', 'reopened', 'updated', 'resolved')
    ),
    CONSTRAINT finding_events_previous_status_valid CHECK (
        previous_status IS NULL OR previous_status IN ('open', 'resolved')
    ),
    CONSTRAINT finding_events_new_status_valid CHECK (
        new_status IN ('open', 'resolved')
    ),
    CONSTRAINT finding_events_severity_valid CHECK (
        severity IN ('informational', 'low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT finding_events_reason_valid CHECK (
        reason IN (
            'exposure_open',
            'exposure_reopened',
            'service_changed',
            'address_changed',
            'rule_changed',
            'exposure_closed',
            'ownership_removed',
            'rule_disabled',
            'rule_no_longer_matches',
            'reconciliation_repair'
        )
    ),
    CONSTRAINT finding_events_version_positive CHECK (finding_version > 0),
    CONSTRAINT finding_events_source_kind_valid CHECK (
        source_kind IN ('scan_attempt', 'target_event', 'reconciliation')
    ),
    CONSTRAINT finding_events_source_key_nonempty CHECK (btrim(source_key) <> ''),
    CONSTRAINT finding_events_identity_hash_valid CHECK (
        service_identity_sha256 ~ '^[0-9a-f]{64}$'
    )
);

CREATE INDEX finding_events_fingerprint_idx
    ON act.finding_events (fingerprint, event_sequence DESC);

CREATE INDEX finding_events_attempt_idx
    ON act.finding_events (source_attempt_id)
    WHERE source_attempt_id IS NOT NULL;

CREATE TRIGGER finding_events_append_only
BEFORE UPDATE OR DELETE ON act.finding_events
FOR EACH ROW EXECUTE FUNCTION act.reject_append_only_mutation();

CREATE TABLE act.reconciliation_runs (
    run_key CHAR(64) PRIMARY KEY,
    invocation_key TEXT NOT NULL UNIQUE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    findings_examined INTEGER,
    handoffs_queued INTEGER,
    CONSTRAINT reconciliation_runs_key_valid CHECK (run_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT reconciliation_runs_invocation_nonempty CHECK (btrim(invocation_key) <> ''),
    CONSTRAINT reconciliation_runs_counts_valid CHECK (
        (findings_examined IS NULL OR findings_examined >= 0)
        AND (handoffs_queued IS NULL OR handoffs_queued >= 0)
    ),
    CONSTRAINT reconciliation_runs_completion_valid CHECK (
        completed_at IS NULL
        OR (
            findings_examined IS NOT NULL
            AND handoffs_queued IS NOT NULL
            AND completed_at >= started_at
        )
    )
);

CREATE TABLE act.finding_handoffs (
    handoff_key CHAR(64) PRIMARY KEY,
    fingerprint CHAR(64) NOT NULL REFERENCES act.findings (fingerprint),
    finding_event_key CHAR(64) REFERENCES act.finding_events (event_key),
    run_key CHAR(64) REFERENCES act.reconciliation_runs (run_key),
    source_attempt_id TEXT REFERENCES act.scan_attempts (attempt_id),
    handoff_kind TEXT NOT NULL,
    object_bucket TEXT NOT NULL,
    object_key TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    first_attempted_at TIMESTAMPTZ,
    last_attempted_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    publish_attempts INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT,
    CONSTRAINT finding_handoffs_key_valid CHECK (handoff_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT finding_handoffs_kind_valid CHECK (
        handoff_kind IN ('finding_event', 'current_snapshot')
    ),
    CONSTRAINT finding_handoffs_source_valid CHECK (
        (
            handoff_kind = 'finding_event'
            AND finding_event_key IS NOT NULL
            AND run_key IS NULL
        )
        OR (
            handoff_kind = 'current_snapshot'
            AND finding_event_key IS NULL
            AND run_key IS NOT NULL
        )
    ),
    CONSTRAINT finding_handoffs_bucket_nonempty CHECK (btrim(object_bucket) <> ''),
    CONSTRAINT finding_handoffs_object_key_nonempty CHECK (btrim(object_key) <> ''),
    CONSTRAINT finding_handoffs_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT finding_handoffs_payload_hash_valid CHECK (
        payload_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT finding_handoffs_attempts_nonnegative CHECK (publish_attempts >= 0),
    CONSTRAINT finding_handoffs_attempt_times_valid CHECK (
        (publish_attempts = 0 AND first_attempted_at IS NULL AND last_attempted_at IS NULL)
        OR (
            publish_attempts > 0
            AND first_attempted_at IS NOT NULL
            AND last_attempted_at IS NOT NULL
            AND last_attempted_at >= first_attempted_at
        )
    )
);

CREATE INDEX finding_handoffs_pending_idx
    ON act.finding_handoffs (created_at, handoff_key)
    WHERE published_at IS NULL;

CREATE INDEX finding_handoffs_attempt_idx
    ON act.finding_handoffs (source_attempt_id)
    WHERE source_attempt_id IS NOT NULL;

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

CREATE TABLE act.database_connect_baseline (
    database_name NAME PRIMARY KEY,
    public_connect BOOLEAN NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE act.application_role_grants (
    role_name NAME PRIMARY KEY,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

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

CREATE FUNCTION act.grant_application_role_objects(role_to_grant NAME)
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

CREATE FUNCTION act.revoke_application_role_objects(role_to_revoke NAME)
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

CREATE FUNCTION act.grant_application_role(role_to_grant NAME)
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

REVOKE ALL ON SCHEMA act FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA act FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA act FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.reject_append_only_mutation() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.grant_application_role_objects(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.grant_application_role(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role_objects(NAME) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION act.revoke_application_role(NAME) FROM PUBLIC;

COMMENT ON FUNCTION act.grant_application_role_objects(NAME) IS
    'Owner-invoked, fail-closed grant for an existing runtime role; grants no DDL, DELETE, or rule editing.';
COMMENT ON FUNCTION act.grant_application_role(NAME) IS
    'Owner-invoked runtime grant with effective dedicated-database CONNECT and no DDL, DELETE, or rule editing.';
COMMENT ON TABLE act.application_role_grants IS
    'Roles whose direct CONNECT grant is managed by the ACT application-role functions.';
