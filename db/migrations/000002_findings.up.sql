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
