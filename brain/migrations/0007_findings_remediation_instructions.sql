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
