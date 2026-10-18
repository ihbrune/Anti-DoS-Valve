-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 4: IP enrichment attributes, bot/crawler feeds, and IP ranges
-- ============================================================================

-- 1. Extend blocked_client_events with ASN, Geo, and Client Classification
ALTER TABLE blocked_client_events ADD COLUMN asn BIGINT;
ALTER TABLE blocked_client_events ADD COLUMN as_org VARCHAR(255);
ALTER TABLE blocked_client_events ADD COLUMN country_code VARCHAR(2);
ALTER TABLE blocked_client_events ADD COLUMN client_type VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE blocked_client_events ADD COLUMN enrichment_status VARCHAR(16) NOT NULL DEFAULT 'PENDING';

CREATE INDEX IF NOT EXISTS idx_events_enrichment_status ON blocked_client_events(enrichment_status);
CREATE INDEX IF NOT EXISTS idx_events_asn ON blocked_client_events(asn);
CREATE INDEX IF NOT EXISTS idx_events_client_type ON blocked_client_events(client_type);
CREATE INDEX IF NOT EXISTS idx_events_country ON blocked_client_events(country_code);

-- 2. Crawler Feeds table
CREATE TABLE IF NOT EXISTS crawler_feeds (
    feed_key VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    category VARCHAR(32) NOT NULL,
    url VARCHAR(512) NOT NULL,
    last_synced_at TIMESTAMP,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    prefix_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

-- 3. Verified Bot / Crawler IP Ranges table
CREATE TABLE IF NOT EXISTS bot_ip_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_key VARCHAR(64) NOT NULL,
    cidr VARCHAR(64) NOT NULL,
    ip_version SMALLINT NOT NULL DEFAULT 4,
    ip_v4_start BIGINT,
    ip_v4_end BIGINT,
    ip_v6_start VARCHAR(16),
    ip_v6_end VARCHAR(16),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_bot_feed FOREIGN KEY (feed_key) REFERENCES crawler_feeds(feed_key) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_bot_ranges_feed_key ON bot_ip_ranges(feed_key);
CREATE INDEX IF NOT EXISTS idx_bot_ranges_v4 ON bot_ip_ranges(ip_version, ip_v4_start, ip_v4_end);
CREATE INDEX IF NOT EXISTS idx_bot_ranges_v6 ON bot_ip_ranges(ip_version, ip_v6_start, ip_v6_end);
