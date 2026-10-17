-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 1: Initial schema for slot snapshots, client events, and heartbeats
-- ============================================================================

CREATE TABLE IF NOT EXISTS endpoint_heartbeats (
    server_id VARCHAR(100) PRIMARY KEY,
    url VARCHAR(255) NOT NULL,
    is_online BOOLEAN NOT NULL DEFAULT FALSE,
    last_poll_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT,
    response_time_ms INTEGER DEFAULT 0,
    valves_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS slot_snapshots (
    id BIGSERIAL PRIMARY KEY,
    server_id VARCHAR(100) NOT NULL,
    valve_name VARCHAR(100) NOT NULL,
    slot_key BIGINT NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    total_requests BIGINT NOT NULL DEFAULT 0,
    active_counters INTEGER NOT NULL DEFAULT 0,
    blocked_counters INTEGER NOT NULL DEFAULT 0,
    is_completed BOOLEAN NOT NULL DEFAULT FALSE,
    last_polled_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_slot_snapshot UNIQUE (server_id, valve_name, slot_key)
);

CREATE INDEX IF NOT EXISTS idx_slot_server_valve ON slot_snapshots(server_id, valve_name);
CREATE INDEX IF NOT EXISTS idx_slot_start_time ON slot_snapshots(start_time);
CREATE INDEX IF NOT EXISTS idx_slot_completed ON slot_snapshots(is_completed);

CREATE TABLE IF NOT EXISTS blocked_client_events (
    id BIGSERIAL PRIMARY KEY,
    server_id VARCHAR(100) NOT NULL,
    valve_name VARCHAR(100) NOT NULL,
    slot_key BIGINT NOT NULL,
    slot_time TIMESTAMPTZ NOT NULL,
    client_key VARCHAR(64) NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    retained_count INTEGER NOT NULL DEFAULT 0,
    is_locked BOOLEAN NOT NULL DEFAULT TRUE,
    is_completed BOOLEAN NOT NULL DEFAULT FALSE,
    last_updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_client_event UNIQUE (server_id, valve_name, slot_key, client_key)
);

CREATE INDEX IF NOT EXISTS idx_client_key ON blocked_client_events(client_key);
CREATE INDEX IF NOT EXISTS idx_client_slot_time ON blocked_client_events(slot_time);
CREATE INDEX IF NOT EXISTS idx_client_server ON blocked_client_events(server_id);
