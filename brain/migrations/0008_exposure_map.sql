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
