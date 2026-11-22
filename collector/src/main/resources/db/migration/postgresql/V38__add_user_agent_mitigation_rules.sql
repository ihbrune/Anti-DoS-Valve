-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 38: Add active User-Agent mitigation rules & telemetry columns
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN IF NOT EXISTS dynamic_ua_blocks_active_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE monitored_valves ADD COLUMN IF NOT EXISTS dynamic_ua_blocks_blocked_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE monitored_valves ADD COLUMN IF NOT EXISTS dynamic_ua_blocks_bypassed_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE monitored_valves ADD COLUMN IF NOT EXISTS dynamic_ua_rules_revision BIGINT NOT NULL DEFAULT 0;

ALTER TABLE mitigation_audit_log ADD COLUMN IF NOT EXISTS target_type VARCHAR(16) NOT NULL DEFAULT 'CIDR';
CREATE INDEX IF NOT EXISTS idx_mitigation_audit_target_type ON mitigation_audit_log(target_type);

CREATE TABLE IF NOT EXISTS mitigation_ua_rules (
    id BIGSERIAL PRIMARY KEY,
    user_agent_hash VARCHAR(64) NOT NULL,
    ua_hash_32 INTEGER NOT NULL,
    raw_user_agent TEXT NOT NULL,
    browser_family VARCHAR(64) NOT NULL DEFAULT 'OTHER',
    target_scope VARCHAR(128) NOT NULL DEFAULT 'ALL',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    source VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
    batch_id VARCHAR(64),
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    total_blocked_hits BIGINT NOT NULL DEFAULT 0,
    total_bypassed_hits BIGINT NOT NULL DEFAULT 0,
    last_hit_at TIMESTAMPTZ,
    CONSTRAINT uq_mitigation_ua_scope UNIQUE (user_agent_hash, target_scope)
);

CREATE INDEX IF NOT EXISTS idx_mitigation_ua_status_expires ON mitigation_ua_rules(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_mitigation_ua_hash32 ON mitigation_ua_rules(ua_hash_32);
CREATE INDEX IF NOT EXISTS idx_mitigation_ua_updated ON mitigation_ua_rules(updated_at DESC);
