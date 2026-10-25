-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 12: Subnet Profiles for baseline frequency, dormancy, and surge tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS subnet_profiles (
    subnet_group VARCHAR(64) PRIMARY KEY,
    first_seen_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL,
    days_dormant_before_last_seen INTEGER NOT NULL DEFAULT 0,
    total_lifetime_requests BIGINT NOT NULL DEFAULT 0,
    total_active_requests BIGINT NOT NULL DEFAULT 0,
    total_blocked_requests BIGINT NOT NULL DEFAULT 0,
    baseline_daily_avg REAL NOT NULL DEFAULT 0.0,
    baseline_distinct_clients INTEGER NOT NULL DEFAULT 1,
    peak_daily_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_distinct_clients INTEGER NOT NULL DEFAULT 0,
    last_24h_blocked_requests BIGINT NOT NULL DEFAULT 0,
    last_24h_surge_factor REAL NOT NULL DEFAULT 1.0,
    asn BIGINT,
    as_org VARCHAR(255),
    country_code VARCHAR(2),
    client_type VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_profiles_last_seen ON subnet_profiles(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_profiles_surge ON subnet_profiles(last_24h_surge_factor);
CREATE INDEX IF NOT EXISTS idx_profiles_dormant ON subnet_profiles(days_dormant_before_last_seen);
CREATE INDEX IF NOT EXISTS idx_profiles_first_seen ON subnet_profiles(first_seen_at);
CREATE INDEX IF NOT EXISTS idx_profiles_asn ON subnet_profiles(asn);
CREATE INDEX IF NOT EXISTS idx_profiles_client_type ON subnet_profiles(client_type);
