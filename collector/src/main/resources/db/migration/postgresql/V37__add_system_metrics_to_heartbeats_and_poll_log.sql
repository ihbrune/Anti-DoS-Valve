-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 37: Add system and runtime resource metrics to heartbeats and poll log
-- ============================================================================

ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS cpu_process REAL;
ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS cpu_system REAL;
ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS system_load_avg REAL;
ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS heap_used_bytes BIGINT;
ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS heap_max_bytes BIGINT;
ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS heap_used_percent REAL;
ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS gc_time_ms BIGINT;
ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS busy_threads INTEGER;
ALTER TABLE endpoint_heartbeats ADD COLUMN IF NOT EXISTS max_threads INTEGER;

ALTER TABLE poll_event_log ADD COLUMN IF NOT EXISTS cpu_process REAL;
ALTER TABLE poll_event_log ADD COLUMN IF NOT EXISTS heap_used_percent REAL;
ALTER TABLE poll_event_log ADD COLUMN IF NOT EXISTS busy_threads INTEGER;
ALTER TABLE poll_event_log ADD COLUMN IF NOT EXISTS max_threads INTEGER;
