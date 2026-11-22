-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 40: Create endpoint_rollups table for target URI forensics & hotspot analytics
-- ============================================================================

CREATE TABLE IF NOT EXISTS endpoint_rollups (
    id BIGSERIAL PRIMARY KEY,
    bucket_start TIMESTAMP NOT NULL,
    server_id VARCHAR(64) NOT NULL DEFAULT 'ALL',
    valve_name VARCHAR(64) NOT NULL DEFAULT 'ALL',
    clean_endpoint VARCHAR(256) NOT NULL,
    sample_method VARCHAR(10) NOT NULL DEFAULT 'GET',
    total_requests BIGINT NOT NULL DEFAULT 0,
    blocked_requests BIGINT NOT NULL DEFAULT 0,
    marked_requests BIGINT NOT NULL DEFAULT 0,
    active_requests BIGINT NOT NULL DEFAULT 0,
    authenticated_requests BIGINT NOT NULL DEFAULT 0,
    internal_requests BIGINT NOT NULL DEFAULT 0,
    crawler_requests BIGINT NOT NULL DEFAULT 0,
    distinct_clients INTEGER NOT NULL DEFAULT 0,
    distinct_subnets INTEGER NOT NULL DEFAULT 0,
    distinct_user_agents INTEGER NOT NULL DEFAULT 0,
    auth_samples INTEGER NOT NULL DEFAULT 0,
    returning_samples INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT uq_endpoint_rollup UNIQUE (bucket_start, server_id, valve_name, clean_endpoint, sample_method)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_rollups_bucket ON endpoint_rollups (bucket_start, total_requests DESC);
CREATE INDEX IF NOT EXISTS idx_endpoint_rollups_clean ON endpoint_rollups (clean_endpoint);
CREATE INDEX IF NOT EXISTS idx_endpoint_rollups_server_valve ON endpoint_rollups (bucket_start, server_id, valve_name);
