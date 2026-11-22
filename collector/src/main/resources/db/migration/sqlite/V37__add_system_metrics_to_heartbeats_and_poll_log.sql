-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 37: Add system and runtime resource metrics to heartbeats and poll log
-- ============================================================================

ALTER TABLE endpoint_heartbeats ADD COLUMN cpu_process REAL;
ALTER TABLE endpoint_heartbeats ADD COLUMN cpu_system REAL;
ALTER TABLE endpoint_heartbeats ADD COLUMN system_load_avg REAL;
ALTER TABLE endpoint_heartbeats ADD COLUMN heap_used_bytes BIGINT;
ALTER TABLE endpoint_heartbeats ADD COLUMN heap_max_bytes BIGINT;
ALTER TABLE endpoint_heartbeats ADD COLUMN heap_used_percent REAL;
ALTER TABLE endpoint_heartbeats ADD COLUMN gc_time_ms BIGINT;
ALTER TABLE endpoint_heartbeats ADD COLUMN busy_threads INTEGER;
ALTER TABLE endpoint_heartbeats ADD COLUMN max_threads INTEGER;

ALTER TABLE poll_event_log ADD COLUMN cpu_process REAL;
ALTER TABLE poll_event_log ADD COLUMN heap_used_percent REAL;
ALTER TABLE poll_event_log ADD COLUMN busy_threads INTEGER;
ALTER TABLE poll_event_log ADD COLUMN max_threads INTEGER;
