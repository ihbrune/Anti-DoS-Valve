-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 9: Create network_annotations table for persistent operator knowledge
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_annotations (
    id BIGSERIAL PRIMARY KEY,
    target_type VARCHAR(16) NOT NULL,            -- 'ASN' or 'SUBNET'
    target_key VARCHAR(64) NOT NULL,             -- e.g. 'AS24940' or '198.51.100.0/24'
    asn BIGINT,                                  -- Numeric ASN for fast exact lookup
    subnet_group VARCHAR(64),                    -- Normalized /24 or /64 prefix string
    ip_version SMALLINT NOT NULL DEFAULT 4,
    cidr_prefix SMALLINT NOT NULL DEFAULT 32,
    ip_v4_start BIGINT,
    ip_v4_end BIGINT,
    ip_v6_start VARCHAR(16),
    ip_v6_end VARCHAR(16),
    verdict VARCHAR(32) NOT NULL DEFAULT 'INFO', -- 'LEGITIMATE', 'INTERNAL', 'SUSPICIOUS', 'MALICIOUS', 'INFO'
    note_markdown TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_annotation_target UNIQUE (target_type, target_key)
);

CREATE INDEX IF NOT EXISTS idx_annot_target ON network_annotations(target_type, target_key);
CREATE INDEX IF NOT EXISTS idx_annot_asn ON network_annotations(asn);
CREATE INDEX IF NOT EXISTS idx_annot_subnet ON network_annotations(subnet_group);
CREATE INDEX IF NOT EXISTS idx_annot_v4 ON network_annotations(ip_version, ip_v4_start, ip_v4_end);
CREATE INDEX IF NOT EXISTS idx_annot_v6 ON network_annotations(ip_version, ip_v6_start, ip_v6_end);
CREATE INDEX IF NOT EXISTS idx_annot_updated ON network_annotations(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_annot_verdict ON network_annotations(verdict);
