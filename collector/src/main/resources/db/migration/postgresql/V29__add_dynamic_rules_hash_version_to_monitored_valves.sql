-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 29: Add dynamic rules hash version to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN dynamic_rules_hash_version INTEGER NOT NULL DEFAULT 1;

