-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 39: Add composite index for fast time-window rollups by server and valve
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_rollups_bucket_server_valve ON client_subnet_rollups(bucket_start, server_id, valve_name);
