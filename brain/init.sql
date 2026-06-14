-- Generated from brain/migrations via python3 brain/render_init_sql.py --write

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS assets (
    asset_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    preferred_name TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    role TEXT,
    role_confidence NUMERIC(4,3),
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS asset_identifiers (
    identifier_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    identifier_type TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    UNIQUE(identifier_type, identifier_value)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    scan_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS network_observations (
    observation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id UUID NOT NULL REFERENCES scan_runs(scan_run_id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(asset_id) ON DELETE SET NULL,
    ip_address INET,
    mac_address MACADDR,
    mac_vendor TEXT,
    reachable BOOLEAN,
    port INTEGER,
    protocol TEXT,
    service_name TEXT,
    service_product TEXT,
    service_version TEXT,
    os_guess TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    fingerprint_hash TEXT NOT NULL,
    fingerprint_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS changes (
    change_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    change_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence NUMERIC(4,3) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence NUMERIC(4,3) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    recommended_action TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS classification_lookup (
    lookup_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signature_hash TEXT NOT NULL UNIQUE,
    signature_json JSONB NOT NULL,
    role TEXT NOT NULL,
    confidence NUMERIC(4,3) NOT NULL,
    source TEXT NOT NULL DEFAULT 'llm_learned',
    sample_count INTEGER NOT NULL DEFAULT 1,
    first_learned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_learned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rescan_requests (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    target_ip INET,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL DEFAULT 'ui',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'operator',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    session_token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS enrichment_modules (
    module_key TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS raw_data_sources (
    source_key TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lynis_targets (
    asset_id UUID PRIMARY KEY REFERENCES assets(asset_id) ON DELETE CASCADE,
    ssh_host TEXT NOT NULL,
    ssh_port INTEGER NOT NULL DEFAULT 22,
    ssh_username TEXT NOT NULL,
    ssh_password TEXT,
    use_sudo BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lynis_runs (
    run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    requested_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    source TEXT NOT NULL DEFAULT 'lynis_runner',
    target_ip INET,
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    report_text TEXT,
    log_text TEXT,
    error_text TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS fingerbank_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    evidence_hash TEXT NOT NULL,
    evidence_json JSONB NOT NULL,
    sources_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fingerbank_evidence_asset_created
    ON fingerbank_evidence (asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fingerbank_evidence_hash
    ON fingerbank_evidence (evidence_hash);

CREATE TABLE IF NOT EXISTS fingerbank_matches (
    match_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    evidence_hash TEXT NOT NULL,
    fingerbank_device_id INTEGER,
    device_name TEXT,
    device_version TEXT,
    device_hierarchy TEXT,
    manufacturer_name TEXT,
    score NUMERIC,
    can_be_more_precise BOOLEAN,
    mapped_role TEXT,
    mapped_confidence NUMERIC,
    response_json JSONB NOT NULL,
    matched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fingerbank_matches_asset_matched
    ON fingerbank_matches (asset_id, matched_at DESC);
CREATE INDEX IF NOT EXISTS idx_fingerbank_matches_hash
    ON fingerbank_matches (evidence_hash);

CREATE TABLE IF NOT EXISTS fingerbank_role_mappings (
    mapping_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerbank_device_id INTEGER,
    device_name_pattern TEXT,
    manufacturer_pattern TEXT,
    hierarchy_pattern TEXT,
    mapped_role TEXT NOT NULL,
    default_confidence NUMERIC NOT NULL DEFAULT 0.70,
    priority INTEGER NOT NULL DEFAULT 100,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_fingerbank_role_mappings_device_id
    ON fingerbank_role_mappings (fingerbank_device_id)
    WHERE fingerbank_device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_fingerbank_role_mappings_priority
    ON fingerbank_role_mappings (priority DESC);

CREATE TABLE IF NOT EXISTS finding_remediation_instructions (
    instruction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    requested_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    instruction_text TEXT NOT NULL,
    intent TEXT NOT NULL DEFAULT 'fix',
    priority TEXT NOT NULL DEFAULT 'normal',
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (char_length(btrim(instruction_text)) > 0),
    CHECK (intent IN ('fix', 'investigate', 'defer', 'accept_risk', 'note')),
    CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    CHECK (status IN ('queued', 'in_progress', 'completed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS idx_finding_remediation_instructions_finding_created
    ON finding_remediation_instructions (finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_remediation_instructions_status_priority
    ON finding_remediation_instructions (status, priority, created_at DESC);

CREATE TABLE IF NOT EXISTS exposure_routes (
    route_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source TEXT NOT NULL,
    domain TEXT NOT NULL,
    scheme TEXT,
    upstream_host TEXT,
    upstream_port INTEGER,
    tls_status TEXT,
    certificate_status TEXT,
    force_ssl BOOLEAN,
    http2_support BOOLEAN,
    block_exploits BOOLEAN,
    websocket_support BOOLEAN,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(source, domain, upstream_host, upstream_port)
);

CREATE INDEX IF NOT EXISTS idx_exposure_routes_domain
    ON exposure_routes (domain);
CREATE INDEX IF NOT EXISTS idx_exposure_routes_observed
    ON exposure_routes (observed_at DESC);

CREATE TABLE IF NOT EXISTS exposure_dns_records (
    dns_record_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL,
    resolver TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'observed',
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(hostname, resolver, record_type, record_value)
);

CREATE INDEX IF NOT EXISTS idx_exposure_dns_hostname
    ON exposure_dns_records (hostname);
CREATE INDEX IF NOT EXISTS idx_exposure_dns_status
    ON exposure_dns_records (status);

CREATE TABLE IF NOT EXISTS exposure_launcher_links (
    launcher_link_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    normalized_host TEXT,
    link_kind TEXT NOT NULL DEFAULT 'unknown',
    preferred_route_domain TEXT,
    hygiene_status TEXT NOT NULL DEFAULT 'observed',
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(source, title, url)
);

CREATE INDEX IF NOT EXISTS idx_exposure_launcher_kind
    ON exposure_launcher_links (link_kind);
CREATE INDEX IF NOT EXISTS idx_exposure_launcher_hygiene
    ON exposure_launcher_links (hygiene_status);

CREATE TABLE IF NOT EXISTS exposure_findings (
    exposure_finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    CHECK (status IN ('open', 'accepted', 'resolved', 'dismissed'))
);

CREATE INDEX IF NOT EXISTS idx_exposure_findings_status_severity
    ON exposure_findings (status, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_exposure_findings_type
    ON exposure_findings (finding_type);
