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
