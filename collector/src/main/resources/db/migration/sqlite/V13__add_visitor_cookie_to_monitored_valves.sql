-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 13: Add visitor cookie tracking configuration to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN visitor_cookie_enabled BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE monitored_valves ADD COLUMN visitor_cookie_name VARCHAR(64) NOT NULL DEFAULT '_adv';
