-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 23: Add relevant_auth_scope to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN relevant_auth_scope VARCHAR(32) NOT NULL DEFAULT 'ALL';

