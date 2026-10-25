-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 8: Create monitored_valves table for persistent Valve runtime configurations
-- ============================================================================

CREATE TABLE IF NOT EXISTS monitored_valves (
    server_id VARCHAR(100) NOT NULL,
    valve_name VARCHAR(100) NOT NULL,
    description TEXT,
    pipeline_order INTEGER NOT NULL DEFAULT 0,
    monitor_mode VARCHAR(32) NOT NULL DEFAULT 'BLOCKING',
    simulation_mode BOOLEAN NOT NULL DEFAULT 0,
    server_wide_blocking BOOLEAN NOT NULL DEFAULT 0,
    http_status_code INTEGER NOT NULL DEFAULT 429,
    allowed_requests_per_slot INTEGER NOT NULL,
    slot_length INTEGER NOT NULL,
    number_of_slots INTEGER NOT NULL,
    share_of_retained_former_requests REAL NOT NULL DEFAULT 0.8,
    ipv4_subnet_mask INTEGER NOT NULL DEFAULT 32,
    ipv6_subnet_mask INTEGER NOT NULL DEFAULT 64,
    max_ip_cache_size INTEGER NOT NULL DEFAULT 10000,
    max_blocked_ip_cache_size INTEGER NOT NULL DEFAULT 10000,
    relevant_paths TEXT,
    non_relevant_paths TEXT,
    always_allowed_ips TEXT,
    always_forbidden_ips TEXT,
    status_uri VARCHAR(255),
    status_allowed_ips TEXT,
    last_updated_at TIMESTAMP NOT NULL,
    config_hash INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (server_id, valve_name)
);

CREATE INDEX IF NOT EXISTS idx_monitored_valves_server ON monitored_valves(server_id);
