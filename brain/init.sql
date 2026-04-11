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
