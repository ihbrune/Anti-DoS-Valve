-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 41: Add mitigation_bypass_private_ips and mitigation_bypass_ips to monitored_valves
-- ============================================================================

ALTER TABLE monitored_valves ADD COLUMN mitigation_bypass_private_ips BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE monitored_valves ADD COLUMN mitigation_bypass_ips TEXT;
