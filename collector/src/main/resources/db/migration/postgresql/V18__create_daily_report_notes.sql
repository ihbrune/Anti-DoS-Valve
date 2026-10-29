-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 18: Create daily_report_notes table for operator notes per date
-- ============================================================================

CREATE TABLE IF NOT EXISTS daily_report_notes (
    id BIGSERIAL PRIMARY KEY,
    report_date VARCHAR(10) NOT NULL UNIQUE,      -- 'YYYY-MM-DD'
    note_markdown TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_daily_notes_date ON daily_report_notes(report_date);

