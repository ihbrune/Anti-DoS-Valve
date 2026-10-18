-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 3: Network attributes for IPv4 / IPv6 ranges and subnet rollups
-- ============================================================================

ALTER TABLE blocked_client_events ADD COLUMN ip_version SMALLINT NOT NULL DEFAULT 4;
ALTER TABLE blocked_client_events ADD COLUMN cidr_prefix SMALLINT NOT NULL DEFAULT 32;
ALTER TABLE blocked_client_events ADD COLUMN ip_v4_start BIGINT;
ALTER TABLE blocked_client_events ADD COLUMN ip_v4_end BIGINT;
ALTER TABLE blocked_client_events ADD COLUMN ip_v6_start VARCHAR(16);
ALTER TABLE blocked_client_events ADD COLUMN ip_v6_end VARCHAR(16);
ALTER TABLE blocked_client_events ADD COLUMN subnet_group VARCHAR(64);

UPDATE blocked_client_events SET subnet_group = client_key WHERE subnet_group IS NULL;

CREATE INDEX IF NOT EXISTS idx_events_filter ON blocked_client_events(slot_time, server_id, valve_name);
CREATE INDEX IF NOT EXISTS idx_events_v4_range ON blocked_client_events(ip_version, ip_v4_start, ip_v4_end);
CREATE INDEX IF NOT EXISTS idx_events_v6_range ON blocked_client_events(ip_version, ip_v6_start, ip_v6_end);
CREATE INDEX IF NOT EXISTS idx_events_subnet_group ON blocked_client_events(subnet_group);
