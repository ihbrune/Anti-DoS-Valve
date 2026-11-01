# Anti-DoS Collector: Database Forensics & SQL Runbook

This runbook serves as an investigative guide and SQL cookbook for Site Reliability Engineers (SREs), security analysts, and AI coding assistants. It documents the real-world data patterns, diagnostic queries, and capacity management strategies discovered in production environments protected by the **Anti-DoS Valve** and monitored by the **Anti-DoS Collector**.

---

## 1. Architectural Overview & Volume Tiers

The Collector aggregates telemetry from distributed Apache Tomcat Valve instances across multiple data centers. It supports both **SQLite** (default zero-ops embedded database with WAL mode) and **PostgreSQL 14+** (multi-server enterprise setups).

Database schemas (managed via versioned Flyway migrations from `V1` to `V22`) divide data into three distinct volume and lifecycle tiers:

```
+-----------------------------------------------------------------------------------+
| 1. High-Volume Telemetry (Transient / 1-3 Days Retention)                         |
|    - client_events       : Raw IP-level request/block/mark telemetry (~Millions)   |
|    - slot_snapshots      : Valve slot window counters, peak req/s, dropped counters|
|    - poll_event_log      : Collector scraping audit trail, latency, HTTP status    |
+-----------------------------------------------------------------------------------+
                                        | (Rollup Aggregation Service - 1h/24h)
                                        v
+-----------------------------------------------------------------------------------+
| 2. Aggregated Forensic Rollups (Long-Term / 30-180 Days Retention)                |
|    - client_subnet_rollups: Subnet (/24 or /64) partitioned metrics, client type,   |
|                            returning/auth ratio, distinct UAs, ASN, country       |
|    - subnet_profiles     : Welford-based 30-day rolling baselines (mean, variance) |
|    - daily_operational_reports: Permanent daily audit records                     |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 3. Metadata & Configuration (Permanent / Config State)                            |
|    - monitored_valves    : Discovered/configured valves, limits, regex whitelists  |
|    - subnet_notes        : Analyst investigation notes, tags, annotations          |
|    - threat_intel_ranges : Known Tor exit nodes, crawler feeds, cloud subnets      |
+-----------------------------------------------------------------------------------+
```

---

## 2. Storage, Capacity & Bloat Diagnostics

### 2.1 The "98.7% ACTIVE Event" Storage Bottleneck

In high-throughput environments, legitimate users make millions of normal HTTP requests. If the collector records every sample without differential filtering, the `client_events` table grows by gigabytes per day with purely benign (`ACTIVE`) traffic.

Run this diagnostic query to inspect your event distribution:

```sql
-- Event type distribution in client_events
SELECT 
    event_type,
    COUNT(*) AS total_rows,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM client_events), 2) AS percentage,
    MIN(event_time) AS oldest_record,
    MAX(event_time) AS newest_record
FROM client_events
GROUP BY event_type
ORDER BY total_rows DESC;
```

**Diagnostic Interpretation:**
* **`ACTIVE` > 95%:** Normal benign requests dominate storage. These can be safely purged after 24 hours because historical trends are already preserved in `client_subnet_rollups`.
* **`BLOCKED` or `MARKED` events:** High-value forensic evidence of rate-limiting incidents and abusive clients. These should be retained longer (e.g. 7 to 30 days).

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
SELECT 'monitored_valves', COUNT(*) FROM monitored_valves;
```

### 2.3 Manual Differential Purge & Vacuum Guidelines (SQLite)

When operating with SQLite, deleting rows does not automatically shrink file size on disk unless `VACUUM` or auto-vacuum is run. Furthermore, long-running transactions should never block WAL checkpoints.

```sql
-- 1. Check SQLite page count and freelist (unused allocated space)
PRAGMA page_count;
PRAGMA freelist_count;

-- 2. Inspect WAL status
PRAGMA wal_checkpoint(PASSIVE);

-- 3. Execute differential purge manually if retention worker was paused:
-- Delete ACTIVE events older than 24 hours while keeping BLOCKED incidents:
DELETE FROM client_events 
WHERE event_type = 'ACTIVE' 
  AND event_time < datetime('now', '-1 day');

-- 4. Reclaim disk space during off-peak maintenance:
VACUUM;
```

---

## 3. False-Positive & Rate-Limit Tuning Forensics

### 3.1 Detecting Blocked Internal Infrastructure (RFC 1918)

A common misconfiguration occurs when internal microservices, ingress proxies, health checkers, or corporate intranets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are routed through external-facing Anti-DoS Valves without being whitelisted in `alwaysAllowedIPs`.

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
1. Note the `subnet_group` (e.g. `10.77.25.0/24`).
2. Convert CIDR to Tomcat regex: `10\.77\.25\..*`.
3. Merge with `v.always_allowed_ips` in Tomcat's `server.xml`:
   ```xml
   <Valve className="org.henbru.antidos.AntiDoSValve"
          monitorName="FUER-EXTERNE"
          alwaysAllowedIPs="129\.70\..*|10\.77\.25\..*" />
   ```

### 3.2 Detecting Verified Search Engine Drops (Bingbot, Googlebot, Applebot)

Crawlers crawl aggressively, often bursting above standard interactive browsing thresholds (e.g. 50 req/slot). Unless whitelisted or segregated to dedicated paths, search indexing will suffer HTTP 429 drops.

```sql
-- Search engine subnets hitting rate limits
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

### 3.3 Carrier-Grade NAT (CGNAT) & Residential False Positives

When hundreds of mobile users or residential subscribers share an external IPv4 address via Carrier-Grade NAT (e.g. Vodafone, Deutsche Telekom, Comcast), an IP-level valve (`ipv4SubnetMask="32"`) can mistakenly block the entire gateway.

```sql
-- High-volume residential clusters with high returning users being blocked
SELECT 
    r.server_id,
    r.valve_name,
    r.subnet_group,
    r.as_org,
    r.country_code,
    SUM(r.distinct_clients) AS distinct_clients,
    SUM(r.total_requests) AS total_requests,
    SUM(r.blocked_requests) AS blocked_requests,
    SUM(r.returning_requests) AS returning_requests,
    ROUND(SUM(r.returning_requests) * 100.0 / NULLIF(SUM(r.total_requests), 0), 1) AS returning_ratio_pct
FROM client_subnet_rollups r
WHERE r.client_type = 'RESIDENTIAL'
  AND r.blocked_requests > 0
GROUP BY r.server_id, r.valve_name, r.subnet_group, r.as_org, r.country_code
HAVING returning_ratio_pct >= 40.0
ORDER BY blocked_requests DESC;
```

**Remediation Options:**
1. Enable Visitor Cookie Tracking (`visitorCookieEnabled="true"`, `visitorCookieName="_adv"`). E.g., returning users receive individual cookie tracking instead of being grouped strictly by IP.
2. If multiple IPs belong to the same household/office, adjust `ipv4SubnetMask="24"` and increase `allowedRequestsPerSlot` proportionately.

---

## 4. Modern Telemetry Dimensions: User-Agents, Cookies & Authentication

> **Note on Telemetry Availability:**  
> The queries in this section leverage features introduced in Schema `V14` (Visitor Cookie & Authentication Tracking) and `V22` (`distinct_user_agents` fingerprinting). If metrics return `0`, verify that the target Valve node has `visitorCookieEnabled="true"` or `authTrackingEnabled="true"` configured.

### 4.1 User-Agent Rotation vs. Headless Browser Scraping

Scraping frameworks (Playwright, Puppeteer, Selenium) typically randomize HTTP `User-Agent` headers across requests from a small set of proxy IPs. Conversely, standard corporate offices have many clients sharing a few common browser strings.

```sql
-- Detect User-Agent Spoofing / Randomization in subnets
SELECT 
    subnet_group,
    as_org,
    client_type,
    distinct_clients,
    distinct_user_agents,
    ROUND(CAST(distinct_user_agents AS REAL) / NULLIF(distinct_clients, 0), 2) AS ua_to_client_ratio,
    total_requests,
    blocked_requests
FROM client_subnet_rollups
WHERE distinct_clients > 0 
  AND distinct_user_agents > distinct_clients * 2
ORDER BY distinct_user_agents DESC
LIMIT 25;
```

**Forensic Signature:**
* `distinct_clients`: 1 or 2
* `distinct_user_agents`: 20 to 50+
* **Conclusion:** Active automated scraper cycling fake browser fingerprints to evade naive UA-based filtering.

### 4.2 Single-User-Agent Bot Fleets

```sql
-- Subnets with massive client count but exactly ONE User-Agent
SELECT 
    subnet_group,
    as_org,
    country_code,
    distinct_clients,
    distinct_user_agents,
    total_requests,
    blocked_requests
FROM client_subnet_rollups
WHERE distinct_clients >= 10 
  AND distinct_user_agents = 1
ORDER BY distinct_clients DESC
LIMIT 20;
```

**Forensic Signature:**
* Distributed botnet or coordinated tool executing uniform software (e.g., custom Python scraper, vulnerability scanner, Mirai/IoT variant).

### 4.3 Business-Critical False-Positives: Blocked Authenticated Users

If authenticated users (logged-in customers) are receiving HTTP 429 Too Many Requests, this represents a high-severity incident causing direct user frustration and revenue loss.

```sql
-- Identify blocked requests that carried verified authentication cookies/headers
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
ORDER BY blocked_requests DESC;
```

### 4.4 Credential Stuffing & Unauthenticated Login Spraying

When a sensitive endpoint (e.g. `/login`, `/auth`, `/oauth/token`) experiences high request volume but has near 0% authenticated traffic, it strongly indicates brute-force credential stuffing.

```sql
-- Subnets generating high traffic with zero authentication tokens
SELECT 
    subnet_group,
    as_org,
    country_code,
    client_type,
    SUM(total_requests) AS total_req,
    SUM(blocked_requests) AS blocked_req,
    SUM(authenticated_requests) AS auth_req,
    MAX(max_requests_per_client) AS peak_req
FROM client_subnet_rollups
WHERE bucket_start >= datetime('now', '-24 hours')
GROUP BY subnet_group, as_org, country_code, client_type
HAVING total_req >= 2000 AND auth_req = 0
ORDER BY total_req DESC
LIMIT 20;
```

---

## 5. Threat Hunting & Incident Investigation

### 5.1 Rotating Residential Proxy Networks (Low-and-Slow Scraping)

Commercial proxy providers (Bright Data, Oxylabs, Smartproxy) route scraping requests through hijacked or incentivized residential devices. Each IP sends only 1–3 requests, evading per-IP rate limits while harvesting data across thousands of rotating residential IPs.

```sql
-- Pinpoint rotating residential proxy clusters:
-- High distinct clients, low requests per client, residential ISP ASN
SELECT 
    subnet_group,
    as_org,
    country_code,
    distinct_clients,
    total_requests,
    ROUND(CAST(total_requests AS REAL) / distinct_clients, 2) AS avg_req_per_client,
    max_requests_per_client,
    slots_active_count
FROM client_subnet_rollups
WHERE client_type = 'RESIDENTIAL'
  AND distinct_clients >= 5
  AND (CAST(total_requests AS REAL) / distinct_clients) <= 4.0
ORDER BY distinct_clients DESC
LIMIT 30;
```

### 5.2 Datacenter High-Volume Scraping Waves & Edge Offloading

Cloud datacenters (AWS, Azure, DigitalOcean, Hetzner, OVH) frequently generate automated scrapers, scanners, and DoS probes. While Anti-DoS Valve successfully terminates these with HTTP 429, parsing HTTP headers and allocating Tomcat worker threads still consumes CPU and socket resources.

```sql
-- Datacenter ASNs generating excessive blocked requests
SELECT 
    COALESCE(asn, 0) AS asn,
    COALESCE(as_org, 'Unknown Cloud Provider') AS provider_name,
    COUNT(DISTINCT subnet_group) AS targeted_subnets,
    SUM(total_requests) AS total_requests,
    SUM(blocked_requests) AS blocked_requests,
    ROUND(SUM(blocked_requests) * 100.0 / NULLIF(SUM(total_requests), 0), 1) AS block_percentage
FROM client_subnet_rollups
WHERE client_type = 'DATACENTER'
GROUP BY asn, as_org
HAVING blocked_requests >= 5000
ORDER BY blocked_requests DESC;
```

**Operational Recommendation:**
If a single Datacenter ASN generates over 100,000 blocked requests per day, configure an upstream drop rule (e.g. AWS WAF, Cloudflare WAF, or host `iptables -A INPUT -s ... -j DROP`) to discard packets before they reach Tomcat's JVM socket accept loop.

### 5.3 Baseline Surge Radar (Deviation from 30-Day Baselines)

The Collector maintains rolling 30-day baselines in `subnet_profiles` calculated via Welford's algorithm (`hourly_mean`, `hourly_variance`, `hourly_stddev`).

```sql
-- Subnets surging significantly above their established historical baseline
SELECT 
    p.subnet_group,
    p.as_org,
    p.country_code,
    p.last_24h_requests,
    ROUND(p.hourly_mean * 24, 1) AS baseline_expected_24h,
    ROUND(p.surge_multiplier_24h, 2) AS surge_ratio,
    p.surge_detected,
    p.last_24h_blocked
FROM subnet_profiles p
WHERE p.surge_detected = 1 OR p.surge_multiplier_24h >= 3.0
ORDER BY p.last_24h_requests DESC
LIMIT 20;
```

### 5.4 Validating Marked Mode (Dry-Run / Canary Deployments)

When testing new, stricter rate limits in production, operators deploy valves in `monitorMode="MARKING"`. In this mode, abusive requests are tagged with HTTP request attributes (`org.henbru.antidos.MARKED`) rather than blocked.

```sql
-- Validate that Marked counters are actively recording without dropping traffic
SELECT 
    s.server_id,
    s.valve_name,
    s.snapshot_time,
    s.active_counters,
    s.marked_counters,
    s.blocked_counters,
    s.peak_request_rate,
    s.peak_marked_rate,
    s.peak_blocked_rate
FROM slot_snapshots s
WHERE s.marked_counters > 0
ORDER BY s.snapshot_time DESC
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
| **Last 1 Hour** | `bucket_start >= datetime('now', '-1 hour')` | `bucket_start >= NOW() - INTERVAL '1 hour'` |
| **Last 24 Hours** | `bucket_start >= datetime('now', '-24 hours')` | `bucket_start >= NOW() - INTERVAL '24 hours'` |
| **Last 7 Days** | `bucket_start >= datetime('now', '-7 days')` | `bucket_start >= NOW() - INTERVAL '7 days'` |
| **Unix Epoch to UTC** | `datetime(ts_millis / 1000, 'unixepoch')` | `to_timestamp(ts_millis / 1000.0)` |
| **Hourly Grouping** | `strftime('%Y-%m-%d %H:00:00', event_time)` | `date_trunc('hour', event_time)` |

### 6.3 Useful Composite Indices for Forensic Queries

If running ad-hoc analytical queries on large standalone databases, ensure the following composite indexes exist (all are provisioned by Flyway migrations):

* `client_events(event_type, event_time)`: Optimizes differential retention sweeps.
* `client_events(server_id, valve_name, event_time)`: Speeds up node-level timeline forensics.
* `client_subnet_rollups(client_type, blocked_requests)`: Optimizes false-positive and crawler detection.
* `client_subnet_rollups(bucket_start, server_id, valve_name)`: Powers dashboard timeline slicing.
* `subnet_profiles(surge_detected, surge_multiplier_24h)`: Powers the Surge Radar table.

