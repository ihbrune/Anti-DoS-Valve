-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 20: Add authentication session tracking configuration to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN auth_tracking_enabled BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE monitored_valves ADD COLUMN auth_tracking_mode VARCHAR(32) NOT NULL DEFAULT 'OFF';
ALTER TABLE monitored_valves ADD COLUMN auth_cookie_name VARCHAR(64);
ALTER TABLE monitored_valves ADD COLUMN auth_login_paths VARCHAR(255);
ALTER TABLE monitored_valves ADD COLUMN auth_session_ttl_seconds INTEGER NOT NULL DEFAULT 900;
ALTER TABLE monitored_valves ADD COLUMN max_auth_cache_size INTEGER NOT NULL DEFAULT 50000;

