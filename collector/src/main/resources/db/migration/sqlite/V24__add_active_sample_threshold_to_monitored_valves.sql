-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 24: Add active_sample_threshold to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN active_sample_threshold INTEGER NOT NULL DEFAULT 0;

