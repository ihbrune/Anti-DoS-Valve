-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 22: Add distinct User-Agent metrics to events, rollups, and profiles
-- ============================================================================

-- 1. Client events raw metric (nullable: NULL = feature inactive or legacy row)
ALTER TABLE client_events ADD COLUMN distinct_user_agents INTEGER;

-- 2. Subnet rollups aggregate metric
ALTER TABLE client_subnet_rollups ADD COLUMN distinct_user_agents INTEGER NOT NULL DEFAULT 0;

-- 3. Subnet profiles 24h metric
ALTER TABLE subnet_profiles ADD COLUMN last_24h_distinct_user_agents INTEGER NOT NULL DEFAULT 0;

