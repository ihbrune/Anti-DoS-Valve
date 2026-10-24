-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 7: Subnet rollups with configurable window duration and signature dimension tables
-- ============================================================================

-- 1. Main aggregate table per subnet, time window, server, and valve
CREATE TABLE IF NOT EXISTS client_subnet_rollups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_start TIMESTAMP NOT NULL,
    bucket_end TIMESTAMP NOT NULL,
    bucket_minutes INTEGER NOT NULL DEFAULT 60,
    server_id VARCHAR(100) NOT NULL,
    valve_name VARCHAR(100) NOT NULL,
    subnet_group VARCHAR(64) NOT NULL,

    -- Aggregated traffic and client metrics
    total_requests BIGINT NOT NULL DEFAULT 0,
    active_requests BIGINT NOT NULL DEFAULT 0,
    blocked_requests BIGINT NOT NULL DEFAULT 0,
    distinct_clients INTEGER NOT NULL DEFAULT 0,
    min_requests_per_client INTEGER DEFAULT 0,
    max_requests_per_client INTEGER DEFAULT 0,
    slots_active_count INTEGER NOT NULL DEFAULT 0,

    -- Subnet enrichment and threat classification
    asn BIGINT,
    as_org VARCHAR(255),
    country_code VARCHAR(2),
    client_type VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_subnet_rollup UNIQUE (bucket_start, server_id, valve_name, subnet_group)
);

CREATE INDEX IF NOT EXISTS idx_rollups_bucket ON client_subnet_rollups(bucket_start);
CREATE INDEX IF NOT EXISTS idx_rollups_subnet ON client_subnet_rollups(subnet_group);
CREATE INDEX IF NOT EXISTS idx_rollups_server_valve ON client_subnet_rollups(server_id, valve_name);
CREATE INDEX IF NOT EXISTS idx_rollups_asn ON client_subnet_rollups(asn);
CREATE INDEX IF NOT EXISTS idx_rollups_client_type ON client_subnet_rollups(client_type);

-- 2. User Agent Dimension Dictionary Table
CREATE TABLE IF NOT EXISTS dim_user_agent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_agent_hash VARCHAR(64) UNIQUE NOT NULL,
    raw_user_agent TEXT NOT NULL,
    browser_family VARCHAR(64),
    is_bot BOOLEAN NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dim_ua_hash ON dim_user_agent(user_agent_hash);

-- 3. Detail signatures per rollup (for User Agents, JA3/4 fingerprints, and auth state)
CREATE TABLE IF NOT EXISTS rollup_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rollup_id BIGINT NOT NULL,
    ua_id BIGINT,
    ja4_fingerprint VARCHAR(64),
    is_authenticated BOOLEAN NOT NULL DEFAULT 0,
    requests BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_rollup FOREIGN KEY (rollup_id) REFERENCES client_subnet_rollups(id) ON DELETE CASCADE,
    CONSTRAINT fk_ua FOREIGN KEY (ua_id) REFERENCES dim_user_agent(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_signatures_rollup ON rollup_signatures(rollup_id);
CREATE INDEX IF NOT EXISTS idx_signatures_ua ON rollup_signatures(ua_id);
