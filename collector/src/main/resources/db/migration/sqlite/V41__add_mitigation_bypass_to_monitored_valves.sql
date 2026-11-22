-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 41: Add mitigation_bypass_private_ips and mitigation_bypass_ips to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN mitigation_bypass_private_ips BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE monitored_valves ADD COLUMN mitigation_bypass_ips TEXT;
