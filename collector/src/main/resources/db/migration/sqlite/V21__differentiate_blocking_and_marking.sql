-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 21: Differentiate hard BLOCKED (HTTP 429) from soft MARKED (marking / simulation mode)
-- ============================================================================

-- 1. Slot snapshots: add marked_counters and reclassify existing marking/simulation valve slots
ALTER TABLE slot_snapshots ADD COLUMN marked_counters INTEGER NOT NULL DEFAULT 0;

UPDATE slot_snapshots
SET marked_counters = blocked_counters,
    blocked_counters = 0
WHERE blocked_counters > 0
  AND EXISTS (
      SELECT 1 FROM monitored_valves mv
      WHERE mv.server_id = slot_snapshots.server_id
        AND mv.valve_name = slot_snapshots.valve_name
        AND (UPPER(mv.monitor_mode) = 'MARKING' OR mv.simulation_mode = 1)
  );

-- 2. Client events: reclassify existing BLOCKED events from marking/simulation valves to MARKED
UPDATE client_events
SET status = 'MARKED'
WHERE status = 'BLOCKED'
  AND EXISTS (
      SELECT 1 FROM monitored_valves mv
      WHERE mv.server_id = client_events.server_id
        AND mv.valve_name = client_events.valve_name
        AND (UPPER(mv.monitor_mode) = 'MARKING' OR mv.simulation_mode = 1)
  );

-- 3. Subnet rollups: add marked_requests and reclassify existing marking/simulation valve rollups
ALTER TABLE client_subnet_rollups ADD COLUMN marked_requests BIGINT NOT NULL DEFAULT 0;

UPDATE client_subnet_rollups
SET marked_requests = blocked_requests,
    blocked_requests = 0
WHERE blocked_requests > 0
  AND EXISTS (
      SELECT 1 FROM monitored_valves mv
      WHERE mv.server_id = client_subnet_rollups.server_id
        AND mv.valve_name = client_subnet_rollups.valve_name
        AND (UPPER(mv.monitor_mode) = 'MARKING' OR mv.simulation_mode = 1)
  );

-- 4. Subnet profiles: add total_marked_requests and last_24h_marked_requests and backfill
ALTER TABLE subnet_profiles ADD COLUMN total_marked_requests BIGINT NOT NULL DEFAULT 0;
ALTER TABLE subnet_profiles ADD COLUMN last_24h_marked_requests BIGINT NOT NULL DEFAULT 0;

UPDATE subnet_profiles
SET last_24h_marked_requests = CASE
        WHEN COALESCE((SELECT SUM(r.blocked_requests) FROM client_subnet_rollups r WHERE r.subnet_group = subnet_profiles.subnet_group), 0) = 0
        THEN last_24h_blocked_requests
        ELSE 0
    END,
    last_24h_blocked_requests = CASE
        WHEN COALESCE((SELECT SUM(r.blocked_requests) FROM client_subnet_rollups r WHERE r.subnet_group = subnet_profiles.subnet_group), 0) = 0
        THEN 0
        ELSE last_24h_blocked_requests
    END,
    total_blocked_requests = COALESCE((
        SELECT SUM(r.blocked_requests)
        FROM client_subnet_rollups r
        WHERE r.subnet_group = subnet_profiles.subnet_group
    ), 0),
    total_marked_requests = COALESCE((
        SELECT SUM(r.marked_requests)
        FROM client_subnet_rollups r
        WHERE r.subnet_group = subnet_profiles.subnet_group
    ), 0)
WHERE subnet_group IN (
    SELECT DISTINCT subnet_group FROM client_subnet_rollups WHERE marked_requests > 0
);

-- 5. Daily reports & poll event log: add marked counters
ALTER TABLE daily_reports ADD COLUMN total_marked BIGINT NOT NULL DEFAULT 0;
ALTER TABLE daily_reports ADD COLUMN peak_marked_per_sec REAL NOT NULL DEFAULT 0.0;
ALTER TABLE poll_event_log ADD COLUMN marked_events_ingested INTEGER DEFAULT 0;
