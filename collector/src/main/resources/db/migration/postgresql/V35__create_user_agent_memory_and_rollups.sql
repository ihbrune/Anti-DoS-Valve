-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 35: Permanent User-Agent profile memory & hourly evaluation rollups
-- Removes unused rollup_signatures cross-table to prevent storage bloat.
-- ============================================================================

DROP TABLE IF EXISTS rollup_signatures;
DROP TABLE IF EXISTS dim_user_agent;

CREATE TABLE dim_user_agent (
    id BIGSERIAL PRIMARY KEY,
    user_agent_hash VARCHAR(64) UNIQUE NOT NULL,
    ua_hash_32 INTEGER NOT NULL DEFAULT 0,
    raw_user_agent TEXT NOT NULL,
    browser_family VARCHAR(64) NOT NULL DEFAULT 'OTHER',
    parsed_major_version INTEGER,
    is_bot BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_lifetime_requests BIGINT NOT NULL DEFAULT 0,
    total_blocked_requests BIGINT NOT NULL DEFAULT 0,
    total_marked_requests BIGINT NOT NULL DEFAULT 0,
    total_authenticated_samples BIGINT NOT NULL DEFAULT 0,
    total_authenticated_requests BIGINT NOT NULL DEFAULT 0,
    total_internal_requests BIGINT NOT NULL DEFAULT 0,
    total_crawler_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_events INTEGER NOT NULL DEFAULT 0,
    last_24h_blocked_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_marked_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_distinct_subnets INTEGER NOT NULL DEFAULT 0,
    last_24h_distinct_asns INTEGER NOT NULL DEFAULT 0,
    last_24h_auth_samples INTEGER NOT NULL DEFAULT 0,
    last_24h_auth_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_internal_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_crawler_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_datacenter_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_residential_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_returning_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_ua_mismatch_requests BIGINT NOT NULL DEFAULT 0,
    auto_verdict VARCHAR(32) NOT NULL DEFAULT 'NEUTRAL',
    auto_pillar VARCHAR(32) NOT NULL DEFAULT 'NONE',
    auto_verdict_reason TEXT,
    auto_evaluated_at TIMESTAMP,
    manual_override VARCHAR(32) NOT NULL DEFAULT 'AUTO',
    operator_note TEXT,
    updated_by VARCHAR(64),
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dim_ua_hash ON dim_user_agent(user_agent_hash);
CREATE INDEX idx_dim_ua_hash32 ON dim_user_agent(ua_hash_32);
CREATE INDEX idx_dim_ua_verdict ON dim_user_agent(auto_verdict);
CREATE INDEX idx_dim_ua_override ON dim_user_agent(manual_override);
CREATE INDEX idx_dim_ua_last24h ON dim_user_agent(last_24h_requests DESC);

CREATE TABLE user_agent_hourly_rollups (
    id BIGSERIAL PRIMARY KEY,
    bucket_start TIMESTAMP NOT NULL,
    bucket_end TIMESTAMP NOT NULL,
    ua_id BIGINT NOT NULL,
    total_requests BIGINT NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0,
    blocked_requests BIGINT NOT NULL DEFAULT 0,
    marked_requests BIGINT NOT NULL DEFAULT 0,
    incident_events INTEGER NOT NULL DEFAULT 0,
    authenticated_samples INTEGER NOT NULL DEFAULT 0,
    authenticated_requests BIGINT NOT NULL DEFAULT 0,
    internal_requests BIGINT NOT NULL DEFAULT 0,
    crawler_requests BIGINT NOT NULL DEFAULT 0,
    datacenter_requests BIGINT NOT NULL DEFAULT 0,
    residential_requests BIGINT NOT NULL DEFAULT 0,
    returning_requests BIGINT NOT NULL DEFAULT 0,
    ua_mismatch_requests BIGINT NOT NULL DEFAULT 0,
    distinct_subnets INTEGER NOT NULL DEFAULT 0,
    distinct_asns INTEGER NOT NULL DEFAULT 0,
    evaluated_verdict VARCHAR(32) NOT NULL DEFAULT 'NEUTRAL',
    evaluated_pillar VARCHAR(32) NOT NULL DEFAULT 'NONE',
    evaluated_reason TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_ua_hourly_rollup UNIQUE (bucket_start, ua_id),
    CONSTRAINT fk_ua_hourly_dim FOREIGN KEY (ua_id) REFERENCES dim_user_agent(id) ON DELETE CASCADE
);

CREATE INDEX idx_ua_rollups_bucket ON user_agent_hourly_rollups(bucket_start);
CREATE INDEX idx_ua_rollups_ua_bucket ON user_agent_hourly_rollups(ua_id, bucket_start DESC);
