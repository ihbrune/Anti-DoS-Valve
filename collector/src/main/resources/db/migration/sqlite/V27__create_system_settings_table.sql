-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 27: Add system_settings table for dynamic runtime configuration
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_settings (
    setting_key VARCHAR(128) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    description VARCHAR(255),
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(64) NOT NULL DEFAULT 'SYSTEM'
);

CREATE INDEX IF NOT EXISTS idx_system_settings_updated ON system_settings(updated_at DESC);

