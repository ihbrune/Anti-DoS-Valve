-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 31: Add always_allow_private_ips to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN always_allow_private_ips BOOLEAN NOT NULL DEFAULT 0;

