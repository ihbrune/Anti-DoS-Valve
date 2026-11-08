-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 26: Add dynamic mitigation guardrails to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN mitigation_min_prefix_v4 INTEGER NOT NULL DEFAULT 16;
ALTER TABLE monitored_valves ADD COLUMN mitigation_min_prefix_v6 INTEGER NOT NULL DEFAULT 32;
ALTER TABLE monitored_valves ADD COLUMN mitigation_max_ttl_seconds INTEGER NOT NULL DEFAULT 86400;
ALTER TABLE monitored_valves ADD COLUMN mitigation_max_active_blocks INTEGER NOT NULL DEFAULT 5000;
