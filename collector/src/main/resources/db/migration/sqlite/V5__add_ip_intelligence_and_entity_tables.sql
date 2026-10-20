-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 5: Normalized IP Intelligence & Network Entity tables
-- ============================================================================

-- 1. Intel Sources (feeds, MMDB, static definitions, manual lists)
CREATE TABLE IF NOT EXISTS intel_source (
    source_key VARCHAR(64) PRIMARY KEY,
    source_type VARCHAR(32) NOT NULL, -- 'FEED', 'STATIC', 'MMDB', 'MANUAL'
    name VARCHAR(128) NOT NULL,
    category VARCHAR(32) NOT NULL,
    url VARCHAR(512),
    version BIGINT NOT NULL DEFAULT 1,
    last_synced_at TIMESTAMP,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    prefix_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

-- 2. Intel Ranges (CIDR network blocks and attributes per source)
CREATE TABLE IF NOT EXISTS intel_range (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key VARCHAR(64) NOT NULL,
    cidr VARCHAR(64) NOT NULL,
    ip_version SMALLINT NOT NULL DEFAULT 4,
    cidr_prefix SMALLINT NOT NULL DEFAULT 32,
    ip_v4_start BIGINT,
    ip_v4_end BIGINT,
    ip_v6_start VARCHAR(16),
    ip_v6_end VARCHAR(16),
    asn BIGINT,
    country_code VARCHAR(2),
    category VARCHAR(32),
    label VARCHAR(128),
    source_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_intel_source FOREIGN KEY (source_key) REFERENCES intel_source(source_key) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_intel_range_source ON intel_range(source_key);
CREATE INDEX IF NOT EXISTS idx_intel_range_v4 ON intel_range(ip_version, ip_v4_start, ip_v4_end);
CREATE INDEX IF NOT EXISTS idx_intel_range_v6 ON intel_range(ip_version, ip_v6_start, ip_v6_end);

-- 3. ASN Information catalog
CREATE TABLE IF NOT EXISTS asn_info (
    asn BIGINT PRIMARY KEY,
    as_org VARCHAR(255),
    category VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    category_source VARCHAR(32) NOT NULL DEFAULT 'DEFAULT',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Network Entity (resolved client_key metadata cache)
CREATE TABLE IF NOT EXISTS network_entity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_key VARCHAR(64) NOT NULL UNIQUE,
    ip_version SMALLINT NOT NULL DEFAULT 4,
    cidr_prefix SMALLINT NOT NULL DEFAULT 32,
    ip_v4_start BIGINT,
    ip_v4_end BIGINT,
    ip_v6_start VARCHAR(16),
    ip_v6_end VARCHAR(16),
    subnet_group VARCHAR(64),
    mmdb_network VARCHAR(64),
    asn BIGINT,
    as_org VARCHAR(255),
    country_code VARCHAR(2),
    client_type VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    tags VARCHAR(255),
    enrichment_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    resolved_at TIMESTAMP,
    resolved_versions VARCHAR(255),
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_entity_client_key ON network_entity(client_key);
CREATE INDEX IF NOT EXISTS idx_entity_v4_range ON network_entity(ip_version, ip_v4_start, ip_v4_end);
CREATE INDEX IF NOT EXISTS idx_entity_v6_range ON network_entity(ip_version, ip_v6_start, ip_v6_end);
CREATE INDEX IF NOT EXISTS idx_entity_subnet_group ON network_entity(subnet_group);
CREATE INDEX IF NOT EXISTS idx_entity_asn ON network_entity(asn);
CREATE INDEX IF NOT EXISTS idx_entity_client_type ON network_entity(client_type);
CREATE INDEX IF NOT EXISTS idx_entity_enrichment_status ON network_entity(enrichment_status);

-- 5. Network Entity Match (provenance mapping between entity and matched intel ranges)
CREATE TABLE IF NOT EXISTS network_entity_match (
    entity_id INTEGER NOT NULL,
    range_id INTEGER NOT NULL,
    matched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (entity_id, range_id),
    CONSTRAINT fk_match_entity FOREIGN KEY (entity_id) REFERENCES network_entity(id) ON DELETE CASCADE,
    CONSTRAINT fk_match_range FOREIGN KEY (range_id) REFERENCES intel_range(id) ON DELETE CASCADE
);

-- 6. Add entity_id foreign key column to blocked_client_events
ALTER TABLE blocked_client_events ADD COLUMN entity_id BIGINT;
CREATE INDEX IF NOT EXISTS idx_events_entity_id ON blocked_client_events(entity_id);

-- 7. Data migration from existing crawler_feeds and bot_ip_ranges
INSERT OR IGNORE INTO intel_source (source_key, source_type, name, category, url, version, last_synced_at, status, prefix_count, last_error)
SELECT feed_key, 'FEED', name, category, url, 1, last_synced_at, status, prefix_count, last_error
FROM crawler_feeds;

INSERT INTO intel_range (source_key, cidr, ip_version, cidr_prefix, ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end, category, label, source_version, created_at)
SELECT
    r.feed_key,
    r.cidr,
    r.ip_version,
    CASE
        WHEN r.cidr LIKE '%/%' THEN CAST(substr(r.cidr, instr(r.cidr, '/') + 1) AS INTEGER)
        ELSE (CASE WHEN r.ip_version = 4 THEN 32 ELSE 128 END)
    END,
    r.ip_v4_start,
    r.ip_v4_end,
    r.ip_v6_start,
    r.ip_v6_end,
    f.category,
    f.name,
    1,
    r.created_at
FROM bot_ip_ranges r
LEFT JOIN crawler_feeds f ON r.feed_key = f.feed_key;

-- 8. Backfill initial network_entity records from existing blocked_client_events
INSERT INTO network_entity (
    client_key, ip_version, cidr_prefix, ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end, subnet_group,
    asn, as_org, country_code, client_type, enrichment_status, first_seen, last_seen
)
SELECT
    client_key,
    MAX(ip_version),
    MAX(cidr_prefix),
    MAX(ip_v4_start),
    MAX(ip_v4_end),
    MAX(ip_v6_start),
    MAX(ip_v6_end),
    MAX(subnet_group),
    MAX(asn),
    MAX(as_org),
    MAX(country_code),
    MAX(client_type),
    MAX(enrichment_status),
    MIN(slot_time),
    MAX(slot_time)
FROM blocked_client_events
WHERE client_key IS NOT NULL
GROUP BY client_key
ON CONFLICT (client_key) DO NOTHING;

-- 9. Link blocked_client_events to newly created network_entity rows
UPDATE blocked_client_events
SET entity_id = (SELECT e.id FROM network_entity e WHERE e.client_key = blocked_client_events.client_key)
WHERE entity_id IS NULL;
