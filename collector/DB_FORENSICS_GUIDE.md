# Anti-DoS Collector: Database Forensics & SQL Runbook

This runbook serves as an investigative guide, analytical cookbook, and capacity management reference for Site Reliability Engineers (SREs), security analysts, and AI coding assistants. It documents real-world data patterns, diagnostic queries, and mitigation strategies discovered in production environments protected by the **Anti-DoS Valve** and monitored by the **Anti-DoS Collector**.

---

## 1. Architectural Overview & Volume Tiers

The Collector aggregates telemetry from distributed Apache Tomcat Valve instances across multiple data centers. It supports both **SQLite** (default zero-ops embedded database with WAL mode) and **PostgreSQL 14+** (multi-server enterprise fleets).

Database schemas (managed via versioned Flyway migrations from `V1` to `V24`) divide data into three distinct volume and lifecycle tiers:

```
+-----------------------------------------------------------------------------------+
| 1. High-Volume Telemetry (Transient / 24h Active, 7-30d Incidents Retention)      |
|    - client_events       : Raw client/subnet request telemetry (~Millions)        |
|    - slot_snapshots      : Valve slot window counters, peak req/s, dropped counters|
|    - poll_event_log      : Collector scraping audit trail, latency, HTTP status    |
+-----------------------------------------------------------------------------------+
                                        | (Rollup Aggregation Service - 15m/60m)
                                        v
+-----------------------------------------------------------------------------------+
| 2. Aggregated Forensic Rollups (Tiered / 7d Benign, 30-180d Incidents Retention) |
|    - client_subnet_rollups: Subnet (/24 or /64) partitioned metrics, client type,   |
|                            returning/auth ratio, distinct UAs, ASN, country       |
|    - subnet_profiles     : Welford-based 30-day rolling baselines (mean, variance) |
|    - daily_reports       : Permanent daily audit records & peak metrics           |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 3. Metadata & Configuration (Permanent / Config State)                            |
|    - monitored_valves    : Discovered/configured valves, limits, activeSampleThresh|
|    - network_annotations : Analyst investigation notes, verdicts, tags, markdown   |
|    - network_entity      : Normalized IP/subnet entity intelligence (MMDB/ASNs)   |
|    - crawler_ip_ranges   : Official verified search engine, bot, and Tor exit feeds|
+-----------------------------------------------------------------------------------+
```

---

## 2. Storage, Capacity & Bloat Diagnostics

### 2.1 The "98.7% ACTIVE Event" Storage Bottleneck in `client_events`

In high-throughput environments, legitimate users make millions of normal HTTP requests. If the collector records every sample without differential filtering, the `client_events` table grows by gigabytes per day with purely benign (`status = 'ACTIVE'`) traffic.

Run this diagnostic query to inspect your event distribution:

```sql
-- Event status distribution in client_events
SELECT 
    status,
    COUNT(*) AS total_rows,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM client_events), 2) AS percentage,
    MIN(slot_time) AS oldest_record,
    MAX(slot_time) AS newest_record
FROM client_events
GROUP BY status
ORDER BY total_rows DESC;
```

**Diagnostic Interpretation:**
* **`ACTIVE` > 95%:** Normal benign requests dominate storage. These are purged automatically every hour after 24 hours (`collector.active-event-retention-hours`) because historical volume trends are preserved in `client_subnet_rollups`.
* **`BLOCKED` or `MARKED` events:** High-value forensic evidence of rate-limiting incidents and abusive clients. These are retained over the full retention window (`collector.retention-days`, e.g. 30 days).

---

### 2.2 Table Sizing & Record Count Quick-Check

```sql
-- Record count across all major collector tables
SELECT 'client_events' AS table_name, COUNT(*) AS row_count FROM client_events
UNION ALL
SELECT 'slot_snapshots', COUNT(*) FROM slot_snapshots
UNION ALL
SELECT 'client_subnet_rollups', COUNT(*) FROM client_subnet_rollups
UNION ALL
SELECT 'poll_event_log', COUNT(*) FROM poll_event_log
UNION ALL
SELECT 'subnet_profiles', COUNT(*) FROM subnet_profiles
UNION ALL
SELECT 'monitored_valves', COUNT(*) FROM monitored_valves
UNION ALL
SELECT 'network_annotations', COUNT(*) FROM network_annotations
UNION ALL
SELECT 'daily_reports', COUNT(*) FROM daily_reports;
```

---

### 2.3 Tiered Compaction for `client_subnet_rollups` (The 83% Long-Tail Rule)

While `client_events` is cleaned up hourly, `client_subnet_rollups` can grow to tens of millions of rows if every transient subnet is kept for 180 days. In real production datasets:
* **~55% of all rows** have `total_requests = 1` and `blocked_requests = 0`.
* **~83% of all rows** have `total_requests <= 5` and zero security incidents.

The Collector executes **Tiered Rollup Compaction** daily at 03:30 AM (`RollupAggregationService`):
1. **Tier 1 (Benign Long-Tail):** Rollups with `blocked_requests = 0 AND marked_requests = 0 AND total_requests <= 5` are purged after `low-activity-rollup-retention-days` (default: 7 days).
2. **Tier 2 (Security Incidents & Substantial Traffic):** Rollups with `blocked_requests > 0`, `marked_requests > 0`, or `total_requests > 5` are retained for the full `rollup-retention-days` (e.g. 30–180 days).

To inspect how many low-activity rows are eligible for compaction:

```sql
-- Inspect low-activity benign rollups eligible for 7-day compaction
SELECT 
    CASE 
        WHEN blocked_requests > 0 OR marked_requests > 0 THEN '1. Security Incident (Keep Long-Term)'
        WHEN total_requests > 5 THEN '2. Substantial Benign Volume (Keep Long-Term)'
        ELSE '3. Low-Activity Long-Tail (Prune after 7 Days)'
    END AS retention_tier,
    COUNT(*) AS row_count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM client_subnet_rollups), 1) AS pct_of_table,
    SUM(total_requests) AS total_requests
FROM client_subnet_rollups
GROUP BY retention_tier
ORDER BY retention_tier;
```

---

### 2.4 Manual Differential Purge & Vacuum Guidelines (SQLite)

When operating with SQLite, deleting rows does not automatically shrink file size on disk unless `VACUUM` or auto-vacuum is run. Long-running transactions should never block WAL checkpoints.

```sql
-- 1. Check SQLite page count and freelist (unused allocated space)
PRAGMA page_count;
PRAGMA freelist_count;

-- 2. Inspect WAL status
PRAGMA wal_checkpoint(PASSIVE);

-- 3. Execute differential purge manually if retention worker was paused:
-- Delete ACTIVE events older than 24 hours while keeping BLOCKED/MARKED incidents:
DELETE FROM client_events 
WHERE status = 'ACTIVE' 
  AND slot_time < datetime('now', '-1 day');

-- 4. Purge benign low-activity rollups older than 7 days:
DELETE FROM client_subnet_rollups
WHERE bucket_start < datetime('now', '-7 days')
  AND blocked_requests = 0
  AND COALESCE(marked_requests, 0) = 0
  AND total_requests <= 5;

-- 5. Reclaim disk space during off-peak maintenance:
VACUUM;
```

---

## 3. False-Positive & Rate-Limit Tuning Forensics

### 3.1 Critical Alert: Blocked Authenticated Users (`AUTHENTICATED_USER_LOCKOUT`)

If authenticated users (logged-in customers, students, or staff) are receiving HTTP 429 Too Many Requests, this represents a high-severity incident causing user lockouts.

```sql
-- Identify valves and subnets blocking logged-in authenticated users
SELECT 
    r.server_id,
    r.valve_name,
    r.subnet_group,
    r.as_org,
    r.client_type,
    SUM(r.authenticated_requests) AS authenticated_requests,
    SUM(r.total_requests) AS total_requests,
    SUM(r.blocked_requests) AS blocked_requests,
    ROUND(SUM(r.authenticated_requests) * 100.0 / NULLIF(SUM(r.total_requests), 0), 1) AS auth_pct
FROM client_subnet_rollups r
WHERE r.authenticated_requests > 0 
  AND r.blocked_requests > 0
GROUP BY r.server_id, r.valve_name, r.subnet_group, r.as_org, r.client_type
ORDER BY blocked_requests DESC
LIMIT 25;
```

**Drill-Down: Finding the Offending URIs via Sample Telemetry:**

```sql
-- Find the exact request paths triggering blocks on authenticated traffic
SELECT 
    server_id,
    valve_name,
    sample_method,
    sample_uri,
    COUNT(*) AS incident_count,
    SUM(request_count) AS total_requests,
    SUM(authenticated_count) AS authenticated_requests,
    sample_user_agent
FROM client_events
WHERE status = 'BLOCKED'
  AND authenticated_count > 0
  AND sample_uri IS NOT NULL
GROUP BY server_id, valve_name, sample_method, sample_uri, sample_user_agent
ORDER BY authenticated_requests DESC
LIMIT 20;
```

**Real-World Production Case Study (IdP CSP Reporter Storm):**
* **Finding:** On `IdP03` and `IdP04`, authenticated users experienced thousands of blocks on `/idp/ContentSecurityPolicyLoggingReporter`. Browsers fired bursts of CSP violation reports simultaneously, exhausting the valve's 50-request limit.
* **Remediation Action:**
  1. Add `/idp/ContentSecurityPolicyLoggingReporter` to `nonRelevantPaths`.
  2. Set `relevantAuthScope="UNAUTHENTICATED"` on public frontend valves so logged-in users are immune to rate-limit lockouts.

---

### 3.2 Detecting Blocked Internal Infrastructure (RFC 1918)

When internal microservices, proxies, or monitoring probes (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) route through external-facing valves without being whitelisted in `alwaysAllowedIPs`:

```sql
-- Subnet rollups: Internal private subnets blocked by valves
SELECT 
    r.server_id,
    r.valve_name,
    r.subnet_group,
    SUM(r.total_requests) AS total_requests,
    SUM(r.blocked_requests) AS blocked_requests,
    ROUND(SUM(r.blocked_requests) * 100.0 / SUM(r.total_requests), 1) AS block_rate_pct,
    MAX(r.max_requests_per_client) AS peak_req_per_client,
    v.allowed_requests_per_slot AS configured_slot_limit,
    v.always_allowed_ips AS current_whitelist
FROM client_subnet_rollups r
JOIN monitored_valves v ON r.server_id = v.server_id AND r.valve_name = v.valve_name
WHERE r.client_type = 'PRIVATE_NETWORK'
  AND r.blocked_requests > 0
GROUP BY r.server_id, r.valve_name, r.subnet_group, v.allowed_requests_per_slot, v.always_allowed_ips
ORDER BY blocked_requests DESC;
```

**Remediation Action:**
1. Note the `subnet_group` (e.g. `10.68.252.0/24`).
2. Convert CIDR to Tomcat regex: `10\.68\.252\..*`.
3. Merge into `alwaysAllowedIPs` in `server.xml`:
   ```xml
   <Valve className="org.henbru.antidos.AntiDoSValve"
          monitorName="FUER-EXTERNE"
          alwaysAllowedIPs="129\.70\..*|10\.68\..*|10\.77\..*" />
   ```

---

### 3.3 Corporate NAT Gateways vs. Chameleon UA-Rotating Scrapers

When multiple users behind an institutional NAT proxy share an IP, they generate multiple User-Agents with a high percentage of authenticated traffic. In contrast, chameleon scrapers rotate fake User-Agents with 0% authentication.

```sql
-- Differentiate Corporate NAT Gateways from Chameleon Scrapers
SELECT 
    subnet_group,
    as_org,
    client_type,
    distinct_clients,
    distinct_user_agents,
    ROUND(CAST(distinct_user_agents AS REAL) / NULLIF(distinct_clients, 0), 2) AS ua_per_client,
    SUM(total_requests) AS total_req,
    SUM(blocked_requests) AS blocked_req,
    SUM(authenticated_requests) AS auth_req,
    ROUND(SUM(authenticated_requests) * 100.0 / NULLIF(SUM(total_requests), 0), 1) AS auth_pct,
    CASE 
        WHEN SUM(authenticated_requests) * 100.0 / NULLIF(SUM(total_requests), 0) >= 20.0 
             THEN 'NAT Gateway (Legitimate Org / University)'
        WHEN CAST(distinct_user_agents AS REAL) / NULLIF(distinct_clients, 0) >= 3.0 
             THEN 'Chameleon Scraper (Bot Rotating User-Agents)'
        ELSE 'Standard Multi-Client Subnet'
    END AS diagnostic_verdict
FROM client_subnet_rollups
WHERE bucket_start >= datetime('now', '-24 hours')
  AND distinct_user_agents >= 5
GROUP BY subnet_group, as_org, client_type, distinct_clients, distinct_user_agents
ORDER BY distinct_user_agents DESC
LIMIT 25;
```

---

### 3.4 Verified Search Engine & Crawler Drops (Googlebot, Bingbot, Applebot)

```sql
-- Search engine and verified crawler subnets hitting rate limits
SELECT 
    r.server_id,
    r.valve_name,
    r.as_org AS crawler_name,
    r.subnet_group,
    r.country_code,
    SUM(r.total_requests) AS total_requests,
    SUM(r.blocked_requests) AS blocked_requests,
    ROUND(SUM(r.blocked_requests) * 100.0 / SUM(r.total_requests), 1) AS block_rate_pct,
    MAX(r.max_requests_per_client) AS peak_req_per_client
FROM client_subnet_rollups r
WHERE r.client_type = 'SEARCH_ENGINE'
  AND r.blocked_requests > 0
GROUP BY r.server_id, r.valve_name, r.as_org, r.subnet_group, r.country_code
ORDER BY blocked_requests DESC;
```

---

## 4. Botnet Forensics: Stealth Waves, Carpet Attacks & ASN Footprints

### 4.1 Detecting Horizontal Stealth Carpet Attacks (e.g. ASN 64496 / ASN 64500)

In distributed horizontal waves, attackers distribute requests across dozens of contiguous `/24` subnets, keeping traffic below both individual `/32` IP limits and `/24` subnet limits:

```sql
-- Detect horizontal subnet carpet attacks across an ASN
SELECT 
    asn,
    as_org,
    COUNT(DISTINCT subnet_group) AS active_24_subnets,
    SUM(distinct_clients) AS estimated_bots,
    SUM(total_requests) AS total_requests,
    SUM(blocked_requests) AS blocked_requests,
    SUM(marked_requests) AS marked_requests,
    ROUND(SUM(blocked_requests) * 100.0 / NULLIF(SUM(total_requests), 0), 2) AS block_pct,
    SUM(authenticated_requests) AS auth_requests,
    ROUND(SUM(authenticated_requests) * 100.0 / NULLIF(SUM(total_requests), 0), 2) AS auth_pct,
    ROUND(CAST(SUM(total_requests) AS REAL) / COUNT(DISTINCT subnet_group), 1) AS avg_req_per_subnet
FROM client_subnet_rollups
WHERE bucket_start >= datetime('now', '-24 hours')
  AND asn IS NOT NULL
GROUP BY asn, as_org
HAVING active_24_subnets >= 15 AND auth_pct < 1.0
ORDER BY total_requests DESC
LIMIT 20;
```

**Forensic Signature of a Horizontal ASN Carpet Attack (e.g. ASN 64496):**
* `active_24_subnets`: 48 contiguous subnets (`198.51.100.0/24` etc.).
* `blocked_requests`: 0 (all stayed below the 5,000 req/slot threshold).
* `auth_requests`: 0.0%.
* `distinct_user_agents`: 1 across all subnets.

---

### 4.2 Bot-Score & Fleet Threat Index per Subnet

A composite formula evaluating request volume, returning visitor ratio, authentication ratio, and User-Agent entropy:

```sql
-- High-precision Bot Threat Scoring across subnets
SELECT 
    subnet_group,
    as_org,
    client_type,
    SUM(total_requests) AS total_req,
    SUM(blocked_requests) AS blocked_req,
    ROUND(SUM(returning_requests) * 100.0 / NULLIF(SUM(total_requests), 0), 1) AS returning_pct,
    ROUND(SUM(authenticated_requests) * 100.0 / NULLIF(SUM(total_requests), 0), 1) AS auth_pct,
    MAX(distinct_user_agents) AS distinct_uas,
    MAX(distinct_clients) AS distinct_clients,
    ROUND(
        (1.0 - (COALESCE(SUM(returning_requests), 0) * 1.0 / NULLIF(SUM(total_requests), 1))) * 40.0 +
        (1.0 - (COALESCE(SUM(authenticated_requests), 0) * 1.0 / NULLIF(SUM(total_requests), 1))) * 40.0 +
        (CASE WHEN MAX(distinct_user_agents) = 1 AND MAX(distinct_clients) > 5 THEN 20.0 ELSE 0.0 END),
        1
    ) AS bot_score_pct
FROM client_subnet_rollups
WHERE bucket_start >= datetime('now', '-24 hours')
GROUP BY subnet_group, as_org, client_type
HAVING total_req >= 1000
ORDER BY bot_score_pct DESC, total_req DESC
LIMIT 30;
```

* **`bot_score_pct >= 90%`**: Unambiguous botnet traffic (zero logins, non-returning throwaway visitors, identical User-Agent across clients).
* **`bot_score_pct <= 20%`**: Normal human audience with high return rate and session authentications.

---

### 4.3 Endpoint & URI Hotspot Analysis (Stripping Session IDs)

When analyzing target URIs from sample telemetry (`client_events.sample_uri`), application frameworks often append `;jsessionid=...` matrix parameters. Use SQL string manipulation to group endpoints cleanly:

```sql
-- Top attacked or scraped application endpoints (normalized URI paths)
SELECT 
    server_id,
    valve_name,
    sample_method,
    CASE 
        WHEN INSTR(sample_uri, ';') > 0 THEN SUBSTR(sample_uri, 1, INSTR(sample_uri, ';') - 1)
        WHEN INSTR(sample_uri, '?') > 0 THEN SUBSTR(sample_uri, 1, INSTR(sample_uri, '?') - 1)
        ELSE sample_uri 
    END AS clean_endpoint,
    COUNT(*) AS incident_count,
    SUM(request_count) AS total_requests,
    SUM(authenticated_count) AS authenticated_requests,
    status
FROM client_events
WHERE sample_uri IS NOT NULL
  AND slot_time >= datetime('now', '-24 hours')
GROUP BY server_id, valve_name, sample_method, clean_endpoint, status
ORDER BY total_requests DESC
LIMIT 25;
```

---

### 4.4 Cloudflare ASN 13335 Forensics: Apple iCloud Private Relay Caution

Operators often mistake Cloudflare (`AS13335`) for pure datacenter scraper traffic. However, Apple routes Safari iCloud Private Relay egress traffic through Cloudflare and Fastly:

```sql
-- Inspect Cloudflare ASN 13335 legitimacy breakdown
SELECT 
    subnet_group,
    SUM(total_requests) AS total_req,
    SUM(blocked_requests) AS blocked_req,
    SUM(authenticated_requests) AS auth_req,
    ROUND(SUM(authenticated_requests) * 100.0 / NULLIF(SUM(total_requests), 0), 1) AS auth_pct,
    ROUND(SUM(returning_requests) * 100.0 / NULLIF(SUM(total_requests), 0), 1) AS returning_pct
FROM client_subnet_rollups
WHERE asn = 13335
GROUP BY subnet_group
ORDER BY total_req DESC
LIMIT 20;
```

> [!CAUTION]
> **Never Blanket-Block ASN 13335!**  
> In real production metrics, Cloudflare traffic shows up to **39.8% authenticated users** and **81.5% returning visitor cookies**. Blanket-blocking ASN 13335 immediately locks out mobile iOS/macOS Safari users.

---

## 5. Valve Configuration & Telemetry Discovery

### 5.1 Auditing Active Valves & Sampling Thresholds

Query the `monitored_valves` table to verify current fleet settings and identify nodes missing forensic active sampling:

```sql
-- Fleet-wide Valve configuration and active sample threshold audit
SELECT 
    server_id,
    valve_name,
    pipeline_order,
    monitor_mode,
    allowed_requests_per_slot || ' req / ' || slot_length || 's' AS rate_limit,
    ipv4_subnet_mask || ' / ' || ipv6_subnet_mask AS subnet_masks,
    collector_integration,
    active_sample_threshold,
    relevant_auth_scope,
    visitor_cookie_enabled,
    auth_tracking_mode,
    is_active
FROM monitored_valves
ORDER BY server_id, pipeline_order;
```

**Audit Checks:**
* If `ipv4_subnet_mask = 24` and `active_sample_threshold = 0`, the valve cannot capture URI/UA forensic samples for attacks that stay below `allowed_requests_per_slot`. Set `activeSampleThreshold="50"`.
* If a frontend valve on an IdP or public app has `relevant_auth_scope = 'ALL'`, consider changing to `UNAUTHENTICATED` to protect authenticated sessions from false-positive lockouts.

---

### 5.2 Validating Marked Mode (Dry-Run / Canary Deployments)

```sql
-- Validate that Marked counters are recording without dropping traffic
SELECT 
    s.server_id,
    s.valve_name,
    s.start_time,
    s.total_requests,
    s.active_counters,
    s.marked_counters,
    s.blocked_counters
FROM slot_snapshots s
WHERE s.marked_counters > 0
ORDER BY s.start_time DESC
LIMIT 20;
```

---

## 6. SRE & Database Performance Tooling Cheat Sheet

### 6.1 Fast SQLite CLI Configuration

When connecting to production SQLite databases via the command line, always configure pragmas to prevent lock contention with the running Collector background thread:

```bash
sqlite3 -header -column antidos-collector.db \
  "PRAGMA busy_timeout=10000; PRAGMA query_only=ON; SELECT COUNT(*) FROM client_events;"
```

### 6.2 Timestamp Formatting Cross-Reference

| Target Timeframe | SQLite Syntax | PostgreSQL Syntax |
|---|---|---|
| **Last 1 Hour** | `slot_time >= datetime('now', '-1 hour')` | `slot_time >= NOW() - INTERVAL '1 hour'` |
| **Last 24 Hours** | `slot_time >= datetime('now', '-24 hours')` | `slot_time >= NOW() - INTERVAL '24 hours'` |
| **Last 7 Days** | `bucket_start >= datetime('now', '-7 days')` | `bucket_start >= NOW() - INTERVAL '7 days'` |
| **Unix Epoch to UTC** | `datetime(ts_millis / 1000, 'unixepoch')` | `to_timestamp(ts_millis / 1000.0)` |
| **Hourly Grouping** | `strftime('%Y-%m-%d %H:00:00', slot_time)` | `date_trunc('hour', slot_time)` |

### 6.3 Exact Table Schema Reference for Analysts

| Table Name | Time Column | Count / Volume Columns | Dimension & Status Columns |
|---|---|---|---|
| **`client_events`** | `slot_time` | `request_count`, `retained_count`, `returning_count`, `authenticated_count` | `status` (`ACTIVE`/`BLOCKED`/`MARKED`), `client_key`, `subnet_group`, `sample_method`, `sample_uri`, `sample_user_agent`, `distinct_user_agents`, `distinct_clients` |
| **`client_subnet_rollups`** | `bucket_start`, `bucket_end` | `total_requests`, `active_requests`, `blocked_requests`, `marked_requests`, `returning_requests`, `authenticated_requests` | `subnet_group`, `asn`, `as_org`, `country_code`, `client_type`, `distinct_clients`, `distinct_user_agents` |
| **`slot_snapshots`** | `start_time`, `end_time` | `total_requests`, `active_counters`, `blocked_counters`, `marked_counters` | `server_id`, `valve_name`, `slot_key`, `is_completed` |
| **`daily_reports`** | `report_date`, `created_at` | `total_requests`, `total_blocked`, `total_marked`, `peak_requests_per_sec`, `peak_blocked_per_sec`, `peak_marked_per_sec` | `status`, `peak_server_id`, `peak_valve_name`, `server_count`, `incident_count`, `report_markdown` |
| **`monitored_valves`** | `last_updated_at` | `allowed_requests_per_slot`, `slot_length`, `number_of_slots`, `active_sample_threshold` | `server_id`, `valve_name`, `monitor_mode`, `relevant_auth_scope`, `collector_integration`, `is_active` |
| **`network_annotations`** | `updated_at`, `created_at` | *(metadata)* | `target_type` (`ASN`/`SUBNET`), `target_key`, `verdict`, `note_markdown` |
