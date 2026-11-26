-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 43: Add counter_scope to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN counter_scope VARCHAR(16) NOT NULL DEFAULT 'CLIENT';
