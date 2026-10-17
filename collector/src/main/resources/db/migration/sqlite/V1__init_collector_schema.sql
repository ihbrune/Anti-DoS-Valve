-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 1: Initial schema for slot snapshots, client events, and heartbeats
-- ============================================================================

CREATE TABLE IF NOT EXISTS endpoint_heartbeats (
    server_id VARCHAR(100) PRIMARY KEY,
    url VARCHAR(255) NOT NULL,
    is_online BOOLEAN NOT NULL DEFAULT 0,
    last_poll_at TIMESTAMP,
    last_success_at TIMESTAMP,
    last_error TEXT,
    response_time_ms INTEGER DEFAULT 0,
    valves_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS slot_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id VARCHAR(100) NOT NULL,
    valve_name VARCHAR(100) NOT NULL,
    slot_key BIGINT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    total_requests BIGINT NOT NULL DEFAULT 0,
    active_counters INTEGER NOT NULL DEFAULT 0,
    blocked_counters INTEGER NOT NULL DEFAULT 0,
    is_completed BOOLEAN NOT NULL DEFAULT 0,
    last_polled_at TIMESTAMP NOT NULL,
    CONSTRAINT uq_slot_snapshot UNIQUE (server_id, valve_name, slot_key)
);

CREATE INDEX IF NOT EXISTS idx_slot_server_valve ON slot_snapshots(server_id, valve_name);
CREATE INDEX IF NOT EXISTS idx_slot_start_time ON slot_snapshots(start_time);
CREATE INDEX IF NOT EXISTS idx_slot_completed ON slot_snapshots(is_completed);

CREATE TABLE IF NOT EXISTS blocked_client_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id VARCHAR(100) NOT NULL,
    valve_name VARCHAR(100) NOT NULL,
    slot_key BIGINT NOT NULL,
    slot_time TIMESTAMP NOT NULL,
    client_key VARCHAR(64) NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    retained_count INTEGER NOT NULL DEFAULT 0,
    is_locked BOOLEAN NOT NULL DEFAULT 1,
    is_completed BOOLEAN NOT NULL DEFAULT 0,
    last_updated_at TIMESTAMP NOT NULL,
    CONSTRAINT uq_client_event UNIQUE (server_id, valve_name, slot_key, client_key)
);

CREATE INDEX IF NOT EXISTS idx_client_key ON blocked_client_events(client_key);
CREATE INDEX IF NOT EXISTS idx_client_slot_time ON blocked_client_events(slot_time);
CREATE INDEX IF NOT EXISTS idx_client_server ON blocked_client_events(server_id);
