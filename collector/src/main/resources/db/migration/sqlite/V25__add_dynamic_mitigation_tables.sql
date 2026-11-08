-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 25: Add dynamic CIDR mitigation tables and valve telemetry columns
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN dynamic_mitigation_enabled BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE monitored_valves ADD COLUMN mitigation_uri VARCHAR(255);
ALTER TABLE monitored_valves ADD COLUMN dynamic_blocks_active_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE monitored_valves ADD COLUMN dynamic_blocks_blocked_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE monitored_valves ADD COLUMN dynamic_rules_revision BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS mitigation_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr VARCHAR(64) NOT NULL,
    ip_version SMALLINT NOT NULL DEFAULT 4,
    prefix_length SMALLINT NOT NULL DEFAULT 24,
    target_scope VARCHAR(128) NOT NULL DEFAULT 'ALL',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    source VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
    batch_id VARCHAR(64),
    reason TEXT,
    asn BIGINT,
    asn_organization VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    revoked_reason TEXT,
    total_blocked_hits BIGINT NOT NULL DEFAULT 0,
    peak_distinct_ips INTEGER NOT NULL DEFAULT 0,
    last_hit_at TIMESTAMP,
    deterrence_state VARCHAR(32) NOT NULL DEFAULT 'OBSERVING',
    CONSTRAINT uq_mitigation_cidr_scope UNIQUE (cidr, target_scope)
);

CREATE INDEX IF NOT EXISTS idx_mitigation_status_expires ON mitigation_rules(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_mitigation_batch ON mitigation_rules(batch_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_updated ON mitigation_rules(updated_at DESC);

CREATE TABLE IF NOT EXISTS mitigation_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id BIGINT,
    cidr VARCHAR(64) NOT NULL,
    batch_id VARCHAR(64),
    action VARCHAR(32) NOT NULL,
    actor VARCHAR(64) NOT NULL DEFAULT 'ADMIN',
    ttl_seconds INTEGER,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mitigation_audit_created ON mitigation_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mitigation_audit_cidr ON mitigation_audit_log(cidr);

