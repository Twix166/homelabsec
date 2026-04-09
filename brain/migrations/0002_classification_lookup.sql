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
