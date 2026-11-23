-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 42: Create ua_mitigation_rollups table and add deterrence_state to mitigation_ua_rules
-- ============================================================================

ALTER TABLE mitigation_ua_rules ADD COLUMN deterrence_state VARCHAR(32) NOT NULL DEFAULT 'OBSERVING';

CREATE TABLE IF NOT EXISTS ua_mitigation_rollups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_start TIMESTAMP NOT NULL,
    server_id VARCHAR(64) NOT NULL DEFAULT 'ALL',
    valve_name VARCHAR(64) NOT NULL DEFAULT 'ALL',
    total_requests BIGINT NOT NULL DEFAULT 0,
    blocked_requests BIGINT NOT NULL DEFAULT 0,
    marked_requests BIGINT NOT NULL DEFAULT 0,
    distinct_ua_rules INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_ua_mitigation_rollup UNIQUE (bucket_start, server_id, valve_name)
);

CREATE INDEX IF NOT EXISTS idx_ua_mitigation_rollups_bucket ON ua_mitigation_rollups (bucket_start);
CREATE INDEX IF NOT EXISTS idx_ua_mitigation_rollups_server_valve ON ua_mitigation_rollups (server_id, valve_name);
