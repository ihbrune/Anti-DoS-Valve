-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 17: Create daily_reports table for permanent operational day summary
-- ============================================================================

CREATE TABLE IF NOT EXISTS daily_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_date VARCHAR(10) NOT NULL UNIQUE,      -- 'YYYY-MM-DD'
    status VARCHAR(32) NOT NULL,                  -- 'NORMAL', 'DEGRADED', 'ATTACK_MITIGATED'
    total_requests BIGINT NOT NULL DEFAULT 0,
    total_blocked BIGINT NOT NULL DEFAULT 0,
    peak_requests_per_sec REAL NOT NULL DEFAULT 0.0,
    peak_blocked_per_sec REAL NOT NULL DEFAULT 0.0,
    peak_valve_name VARCHAR(128),
    peak_server_id VARCHAR(128),
    server_count INT NOT NULL DEFAULT 0,
    incident_count INT NOT NULL DEFAULT 0,
    report_markdown TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_daily_reports_date ON daily_reports(report_date DESC);
CREATE INDEX IF NOT EXISTS idx_daily_reports_created ON daily_reports(created_at DESC);
