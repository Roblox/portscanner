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
    CONSTRAINT target_events_disposition_valid CHECK (NOT (accepted AND stale))
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
        OR (NOT stale_generation AND outcome = 'complete')
    )
);

CREATE INDEX scan_attempts_target_generation_idx
    ON act.scan_attempts (target_id, generation, ingested_at DESC);

CREATE INDEX scan_attempts_pending_latency_idx
    ON act.scan_attempts (ingested_at DESC, source_observed_at);

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
    CONSTRAINT exposure_state_closure_valid CHECK (
        (state = 'open' AND closed_at IS NULL AND closure_reason IS NULL)
        OR (
            state = 'closed'
            AND closed_at IS NOT NULL
            AND closure_reason IN (
                'explicit_closed',
                'explicit_filtered',
                'coverage_absence',
                'ownership_removed'
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
            'ownership_removed'
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
