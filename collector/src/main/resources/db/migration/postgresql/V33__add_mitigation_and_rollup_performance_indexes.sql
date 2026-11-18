-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 33: Composite indexes for fast mitigation, deterrence & rollup scans
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_rollups_asn_bucket ON client_subnet_rollups(asn, bucket_start);
CREATE INDEX IF NOT EXISTS idx_rollups_subnet_bucket ON client_subnet_rollups(subnet_group, bucket_start);
CREATE INDEX IF NOT EXISTS idx_rollups_bucket_asn ON client_subnet_rollups(bucket_start, asn);
CREATE INDEX IF NOT EXISTS idx_events_key_status_time ON client_events(client_key, status, slot_time);
CREATE INDEX IF NOT EXISTS idx_mitigation_status_updated ON mitigation_rules(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_mitigation_status_asn ON mitigation_rules(status, asn);
