-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 11: Add collector_integration column to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN collector_integration VARCHAR(16) NOT NULL DEFAULT 'auto';
