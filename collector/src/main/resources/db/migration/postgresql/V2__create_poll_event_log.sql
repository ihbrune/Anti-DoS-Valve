-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 2: Event log recording data collection polling requests and outcomes
-- ============================================================================

CREATE TABLE IF NOT EXISTS poll_event_log (
    id BIGSERIAL PRIMARY KEY,
    server_id VARCHAR(100) NOT NULL,
    url VARCHAR(255) NOT NULL,
    poll_time TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'SUCCESS', 'WARNING', 'ERROR'
    http_status_code INTEGER DEFAULT 0,
    response_time_ms INTEGER DEFAULT 0,
    valves_polled INTEGER DEFAULT 0,
    slots_ingested INTEGER DEFAULT 0,
    events_ingested INTEGER DEFAULT 0,
    details TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_poll_log_time ON poll_event_log(poll_time DESC);
CREATE INDEX IF NOT EXISTS idx_poll_log_server_time ON poll_event_log(server_id, poll_time DESC);
CREATE INDEX IF NOT EXISTS idx_poll_log_status ON poll_event_log(status);
