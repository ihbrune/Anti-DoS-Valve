-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 16: Add is_active flag to monitored_valves for lifecycle management
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_monitored_valves_active ON monitored_valves(server_id, is_active);
