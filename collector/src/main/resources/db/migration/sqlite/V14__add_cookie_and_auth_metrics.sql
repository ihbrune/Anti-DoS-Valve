-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 14: Add visitor cookie and authenticated request metrics to events, rollups, and profiles
-- ============================================================================

-- 1. Client events raw metrics (nullable: NULL = feature inactive or legacy row)
ALTER TABLE client_events ADD COLUMN returning_count INTEGER;
ALTER TABLE client_events ADD COLUMN authenticated_count INTEGER;

-- 2. Subnet rollups aggregate metrics
ALTER TABLE client_subnet_rollups ADD COLUMN returning_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE client_subnet_rollups ADD COLUMN returning_tracked_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE client_subnet_rollups ADD COLUMN authenticated_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE client_subnet_rollups ADD COLUMN authenticated_tracked_requests BIGINT NOT NULL DEFAULT 0;

-- 3. Subnet profiles 24h metrics
ALTER TABLE subnet_profiles ADD COLUMN last_24h_returning_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE subnet_profiles ADD COLUMN last_24h_returning_tracked_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE subnet_profiles ADD COLUMN last_24h_authenticated_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE subnet_profiles ADD COLUMN last_24h_authenticated_tracked_requests BIGINT NOT NULL DEFAULT 0;
