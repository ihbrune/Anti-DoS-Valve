# Anti-DoS Collector: Setup, Deployment & Operations Guide

This guide is designed for **DevOps Engineers, Site Reliability Engineers (SRE), and System Administrators** installing, deploying, configuring, and operating the **Anti-DoS Collector** in production environments.

For high-level system philosophy and fleet interaction, refer to the [🏗️ Fleet Architecture Guide](README.md).
For user interface navigation and incident forensics, refer to the [📖 Dashboard & Forensics User Guide](DASHBOARD_GUIDE.md).

---

## Architectural Principles

The Anti-DoS Collector is a lightweight, high-performance telemetry aggregator and analytics service built with **Spring Boot 3** and **Java 21**:
* **Decoupled Architecture:** Operates independently of the protected Tomcat servers. If the collector is taken offline or restarted, the `AntiDoSValve` instances continue rate-limiting and protecting applications with zero disruption.
* **Virtual Threads:** Fully leverages Java 21 Virtual Threads (`spring.threads.virtual.enabled=true`) for non-blocking HTTP polling across hundreds of distributed server endpoints.
* **Zero Runtime Overhead on Valves:** The Valve requires zero third-party dependencies. Status endpoints expose a compact JSON payload (`/antidos-status`), which the Collector pulls asynchronously.
* **Dual Database Support:**
  * **SQLite (Default):** Zero-configuration file database with WAL mode and busy timeouts, ideal for small-to-medium single-collector deployments.
  * **PostgreSQL:** Production-grade multi-server relational storage for enterprise fleets.
  * Versioned schema migrations are executed automatically via **Flyway**.

---

## Zero-Configuration Demo Mode

To test the collector without connecting live Tomcat instances:

```bash
# Using the Fat-JAR:
java -jar collector/target/anti-dos-collector-1.7.9.jar demo
# Or with a larger fleet (e.g. 3 instances per server type = 9 total servers A, B, C):
java -jar collector/target/anti-dos-collector-1.7.9.jar demo 3

# Or using Maven:
mvn spring-boot:run -pl collector -Dspring-boot.run.arguments="demo"
```

### What happens in Demo Mode?
* **Database Isolation:** Operates against `antidos-collector-demo.db`. Existing production databases remain untouched.
* **Simulated Multi-Node Fleet:** Boots virtual endpoints (`Demo-Edge-EU`, `Demo-API-Gateway`, `Demo-Staging-Node`).
* **Pre-Seeded 7-Day Telemetry:** Instantly pre-seeds realistic diurnal traffic curves, attack waves, and audit logs.
* Access the UI at **`http://localhost:8090`**.

---

## Quickstart

### 1. Build the Collector
```bash
mvn package -pl collector
```
Produces the executable Spring Boot JAR in `collector/target/anti-dos-collector-1.7.9.jar`.

### 2. Configure Monitored Endpoints
```bash
cp collector/src/main/resources/collector-config.example.yaml collector-config.yaml
```
Edit `collector-config.yaml`:
```yaml
collector:
  poll-interval-seconds: 15
  endpoints:
    - name: "Web-Node-1"
      url: "http://localhost:8080/antidos-status"
      token: "secretToken1"
      poll-intermediate-slots: false
```

### 3. Verify an Endpoint via CLI
```bash
java -jar collector/target/anti-dos-collector-1.7.9.jar test-endpoint \
  --url "http://localhost:8080/antidos-status" \
  --token "secretToken1" \
  --name "Web-Node-1"
```

### 4. Run the Collector
```bash
java -jar collector/target/anti-dos-collector-1.7.9.jar
```
Dashboard available at **`http://localhost:8090`**.

---

## Production Setup & Zero-Friction Update Guide

To run the Collector as a robust, 24/7 background service in production—and ensure that future updates via `git pull` from GitHub will **never** overwrite your configuration, delete your database, or cause git merge conflicts—follow this recommended deployment architecture.

### Decoupling Architecture: Code vs. Configuration vs. Data

| Component | Recommended Location | Purpose |
|---|---|---|
| **Source & Git Repo** | `/opt/anti-dos-valve` or `~/build/Anti-DoS-Valve` | Repository where `git pull` and `mvn package` are executed. Contains **no** runtime credentials or databases. |
| **Service Binary** | `/opt/antidos-collector/anti-dos-collector.jar` | Production Fat-JAR executed by systemd. |
| **Configuration** | `/etc/antidos/collector-config.yaml` | System configuration with server URLs, tokens, and thresholds. **Outside Git**, automatically imported on startup. |
| **Persistent Data** | `/var/lib/antidos/` | SQLite database (`antidos-collector.db`), GeoIP MMDB files, and custom ASN overlays. |

---

### Step-by-Step Production Deployment (Linux & systemd)

#### Step 1: Create Dedicated System User & Directories
```bash
# Create dedicated system user and group (-U)
sudo useradd -r -U -s /bin/false -d /var/lib/antidos -c "Anti-DoS Collector Service" antidos || true

# Create configuration, data, and binary directories
sudo mkdir -p /etc/antidos /var/lib/antidos /opt/antidos-collector
sudo chown -R antidos:antidos /var/lib/antidos /etc/antidos /opt/antidos-collector
```

#### Step 2: Initialize Configuration (`/etc/antidos/collector-config.yaml`)
```bash
sudo cp collector/src/main/resources/collector-config.example.yaml /etc/antidos/collector-config.yaml
sudo chown antidos:antidos /etc/antidos/collector-config.yaml
sudo chmod 600 /etc/antidos/collector-config.yaml
```

Configure endpoints, retention schedules, and offline database paths:
```yaml
server:
  port: 8090

spring:
  datasource:
    url: "jdbc:sqlite:/var/lib/antidos/antidos-collector.db?busy_timeout=60000"

collector:
  poll-interval-seconds: 15
  parallel-fleet-polling: true
  retention-days: 30
  active-event-retention-hours: 24
  poll-log-retention-days: 1
  entity-retention-days: 60
  rollup-window-minutes: 60
  rollup-retention-days: 30
  auto-vacuum-enabled: true
  vacuum-threshold-bytes: 52428800
  slow-poll-threshold-ms: 1000

  enrichment:
    enabled: true
    asn-database-path: "/var/lib/antidos/dbip-asn-lite.mmdb"
    country-database-path: "/var/lib/antidos/dbip-country-lite.mmdb"
    custom-datacenter-asns-file: "/etc/antidos/custom-datacenter-asns.txt"

  endpoints:
    - name: "Edge-Node-01"
      url: "http://10.0.1.10:8080/antidos-status"
      token: "productionSecretToken1"
    - name: "API-Gateway"
      url: "http://10.0.1.20:8080/antidos-status"
      token: "productionSecretToken2"
```

#### Step 3: Install the Executable Binary
```bash
sudo cp collector/target/anti-dos-collector-1.7.9.jar /opt/antidos-collector/anti-dos-collector.jar
sudo chown antidos:antidos /opt/antidos-collector/anti-dos-collector.jar
sudo chmod 750 /opt/antidos-collector/anti-dos-collector.jar
```

#### Step 4: Install Systemd Service Unit (`/etc/systemd/system/antidos-collector.service`)
```ini
[Unit]
Description=Anti-DoS Fleet Collector & Forensics Dashboard
After=network.target

[Service]
Type=simple
User=antidos
Group=antidos
WorkingDirectory=/var/lib/antidos

ExecStart=/usr/bin/java \
    -XX:+UseZGC \
    -Xms128m -Xmx512m \
    -jar /opt/antidos-collector/anti-dos-collector.jar \
    --spring.config.additional-location=file:/etc/antidos/collector-config.yaml

Restart=always
RestartSec=10
LimitNOFILE=65536

# Security Sandboxing
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/antidos
ReadOnlyPaths=/etc/antidos /opt/antidos-collector
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now antidos-collector
sudo systemctl status antidos-collector
```

---

### Frictionless GitHub Updates (`git pull` Workflow)

Because code, configuration, and data are decoupled, updating the service takes seconds without touching active configs:

```bash
# 1. Pull latest source code from GitHub
cd /opt/anti-dos-valve
git pull origin master

# 2. Build the updated executable JAR
mvn package -pl collector -DskipTests

# 3. Replace the active binary
sudo cp collector/target/anti-dos-collector-*.jar /opt/antidos-collector/anti-dos-collector.jar

# 4. Restart the collector service
sudo systemctl restart antidos-collector
```
Upon restart, **Flyway** checks for schema migrations and upgrades tables automatically.

---

## Database Configuration

### SQLite (Default Zero-Ops)
Configured with Write-Ahead Logging (WAL) and busy timeout to ensure non-blocking concurrent reads:
```yaml
spring:
  datasource:
    url: "jdbc:sqlite:/var/lib/antidos/antidos-collector.db?busy_timeout=60000"
```

### PostgreSQL (Production Fleet)
For high-volume multi-node fleets, point Spring Data Source to PostgreSQL:
```yaml
spring:
  datasource:
    url: "jdbc:postgresql://db.internal:5432/antidos_collector"
    username: "antidos"
    password: "securePassword"
    hikari:
      maximum-pool-size: 15
      minimum-idle: 3
```
Flyway automatically creates tables, indexes, and triggers from PostgreSQL migration scripts (`db/migration/postgresql`).

---

## IP Enrichment Setup: ASN & Geo-Location

To resolve Autonomous System Numbers, ISP organizations, and countries:

### 1. Download Free MMDB Databases
* **DB-IP Lite:**
  * [dbip-asn-lite.mmdb.gz](https://db-ip.com/db/download/ip-to-asn-lite)
  * [dbip-country-lite.mmdb.gz](https://db-ip.com/db/download/ip-to-country-lite)
  * Extract to `/var/lib/antidos/`
* **MaxMind GeoLite2:** Alternatively, use `geoipupdate` (typically `/usr/share/GeoIP/`).

### 2. Custom Datacenter ASN Overlay (`custom-datacenter-asns.txt`)
Create `/etc/antidos/custom-datacenter-asns.txt` to override categorization:
```
# Force ASN 12345 to be recognized as Datacenter
+12345

# Whitelist/remove ASN 24940 from Datacenter classification
-24940
```

---

## Data Retention & Storage Hygiene Strategy

Automated background schedules execute hourly and nightly at **03:00 AM** and **03:30 AM**:
1. **Differential Client Event Retention:**
   - **High-Volume Active Events (`active-event-retention-hours: 24`):** Prunes raw `status = 'ACTIVE'` events older than 24 hours via an hourly lightweight maintenance job (`0 15 * * * *`) and during nightly retention cleanup. Raw high-throughput telemetry is aggregated into persistent subnet rollups (`client_subnet_rollups`) before raw pruning.
   - **Security Incidents & Forensics (`retention-days: 30`):** Retains full forensic detail (IP, URI, User-Agent, cookie/auth counters) for `BLOCKED` and `MARKED` events for 30 days.
2. **Raw High-Water Snapshots (`retention-days: 30`):** Prunes completed `slot_snapshots` older than 30 days.
3. **Audit Diagnostics (`poll-log-retention-days: 1`):** Purges diagnostic polling event logs older than 24 hours.
4. **Orphan Entity Cleanup (`entity-retention-days: 60`):** Deletes inactive `network_entity` records with zero remaining associated events.
5. **Persistent Subnet Rollups (`rollup-retention-days: 30`):** Retains aggregated `/24` and `/64` subnet traffic buckets for 30 days (reducing long-term table footprint while preserving 30-day baseline analytics).
6. **SQLite Storage Compaction (`auto-vacuum-enabled: true`, `vacuum-threshold-bytes: 52428800`):** Automatically compacts SQLite standalone database files (`VACUUM`) during nightly retention cleanup if reclaimable freelist space exceeds 50 MB. Can also be triggered on demand via the System Status UI.

---

## Relational Database Schema & Data Model

The database separates real-time transient telemetry, persistent subnet aggregations, daily operational summaries, and normalized network intelligence:

```
 +------------------------+             +------------------------+
 |  endpoint_heartbeats   |             |     poll_event_log     |
 +------------------------+             +------------------------+
 | PK server_id           |<- - - - - - | PK id                  |
 |    url, is_online      |  (logical)  |    server_id, status   |
 +-----------+------------+             |    blocked/marked/     |
             | 1                        |    active_ingested     |
             | (logical)                +------------------------+
             +-------------------------+
             | N                       | N
 +-----------v------------+  +---------v--------------+
 |    monitored_valves    |  |     slot_snapshots     |
 +------------------------+  +------------------------+
 | PK id                  |  | PK id                  |
 | UQ (server, valve_name)|  | UQ (server, valve, key)|
 |    monitor_mode        |  |    total_requests      |
 |    simulation_mode     |  |    active_counters     |
 |    visitor/auth_track  |  |    blocked_counters    |
 +------------------------+  |    marked_counters     |
                             +-----------+------------+
                                         | 1
                                         | (logical)
                                         | N
 +---------------------------------------v-----------------------+
 |                         client_events                         |
 +---------------------------------------------------------------+
 | PK id                                                         |
 | UQ (server_id, valve_name, slot_key, client_key)              |
 |    request_count, retained_count, is_locked                   |
 |    status ('BLOCKED' | 'MARKED' | 'ACTIVE')                   |
 |    returning_count, authenticated_count                       |
 |    ip_version, cidr_prefix, ip_v4_start/end, ip_v6_start/end   |
 |    subnet_group, asn, as_org, country_code, client_type       |
 |    sample_method, sample_uri, sample_user_agent               |
 | FK entity_id -------------------------------------------+     |
 +-----------+---------------------------------------------|-----+
             |                                             |
             | aggregated into                             | N
             | (15/60 min windows)                         | 1
             v                                             v
 +-----------------------------------+     +---------------------+
 |       client_subnet_rollups       |     |   network_entity    |
 +-----------------------------------+     +---------------------+
 | PK id                             |     | PK id               |
 | UQ (bucket_start, server, valve,  |     | UQ client_key       |
 |     subnet_group)                 |     |    ip_v4_start/end  |
 |    total/active/blocked/          |     |    subnet_group     |
 |    marked_requests                |     |    asn, as_org      |
 |    returning/authenticated_reqs   |     |    client_type      |
 |    distinct/min/max_clients       |     +----------+----------+
 |    asn, as_org, client_type       |                | 1
 +-----------+-----------------------+                |
             | 1                                      |
             +-----------------------+                |
             |                       |                |
             | computed into (30d)   | N              | N
             v                       v                v
 +-----------------------+  +----------------+  +---------------------+
 |    subnet_profiles    |  |rollup_signat...|  | network_entity_match|
 +-----------------------+  +----------------+  +---------------------+
 | PK subnet_group       |  | PK id          |  | PK id               |
 |    first/last_seen_at |  | FK rollup_id   |  | FK entity_id        |
 |    days_dormant       |  |    ua_id       |  | FK range_id         |
 |    baseline_daily_avg |  |    req_count   |  +----------+----------+
 |    peak_daily_reqs    |  +----------------+             | N
 |    total/last_24h_reqs|                                 |
 |    total/24h_blocked  |  +-----------------------+      | 1
 |    total/24h_marked   |  |     daily_reports     |  +---v-----------------+
 |    24h_returning/auth |  +-----------------------+  |     intel_range     |
 |    last_24h_surge     |  | PK report_date        |  +---------------------+
 |    asn, client_type   |  |    status, total_reqs |  | PK id               |
 +-----------------------+  |    total_blocked      |  | FK source_key       |
                            |    total_marked       |  |    cidr, category   |
 +-----------------------+  |    peak_req/blk/mrk_s |  +----------+----------+
 |  network_annotations  |  |    markdown_content   |             | N
 +-----------------------+  +-----------------------+             | 1
 | PK id                 |                             +----------v----------+
 | UQ (target_type, key) |  +-----------------------+  |    intel_source     |
 |    category, title    |  |       asn_info        |  +---------------------+
 |    markdown_notes     |  +-----------------------+  | PK source_key       |
 +-----------------------+  | PK asn                |  |    display_name     |
                            |    as_org, category   |  |    category, feed   |
 +------------------------+ +-----------------------+  +---------------------+
 |     crawler_feeds      |
 +------------------------+
 | PK id                  |
 |    feed_name, status   |
 |    etag, last_synced_at|
 +-----------+------------+
             | 1
             | N
 +-----------v------------+
 |     bot_ip_ranges      |
 +------------------------+
 | PK id, FK feed_id      |
 |    bot_name, cidr      |
 |    ip_v4/v6_start/end  |
 +------------------------+
```

### Key Tables Overview
1. **`endpoint_heartbeats`:** Real-time health, latency, online/offline status, and valve discovery per monitored server node.
2. **`monitored_valves`:** Persisted runtime configurations for each discovered Valve (`monitor_mode`, `simulation_mode`, rate-limit thresholds, slot duration, `visitor_cookie_enabled`, and `auth_tracking_enabled`).
3. **`slot_snapshots`:** Completed and active time slots per server and valve instance with total request counts, active counters, hard-blocked counters (`blocked_counters`, HTTP 429), and soft-marked/simulated counters (`marked_counters`).
4. **`client_events`:** Granular rate-limit events distinguishing hard blocks (`status = 'BLOCKED'`), soft-marking/simulation threshold hits (`status = 'MARKED'`), and tracked active clients (`status = 'ACTIVE'`). Stores numeric IPv4/IPv6 boundaries (`ip_v4_start`, `ip_v4_end`) for sub-millisecond range lookups, visitor cookie and authentication counters (`returning_count`, `authenticated_count`), and first-trigger request samples (`sample_method`, `sample_uri`, `sample_user_agent`).
5. **`client_subnet_rollups`:** Persistent time-bucket aggregations per `/24` (IPv4) or `/64` (IPv6) subnet partition tracking `total_requests`, `active_requests`, `blocked_requests`, `marked_requests`, returning visitor / authenticated ratios, distinct client counts, and botnet heuristic metrics.
6. **`subnet_profiles`:** Long-term frequency baselines (30-day lookback with dynamic 3-phase calibration), dormancy periods, 24-hour surge multipliers, lifetime and 24h blocked vs. marked request totals (`total_blocked_requests`, `last_24h_blocked_requests`, `total_marked_requests`, `last_24h_marked_requests`), and 24h visitor cookie / authentication ratios per subnet partition for rapid detection of dormant breakouts and residential proxy sweeps.
7. **`daily_reports`:** Permanent daily operational summaries (`report_date`, `status`, `total_requests`, `total_blocked`, `total_marked`, `peak_requests_per_sec`, `peak_blocked_per_sec`, `peak_marked_per_sec`, and rendered GFM `markdown_content`) archived prior to raw telemetry retention cleanup.
8. **`network_annotations`:** Persistent operator knowledge archive, threat notes, and verdict badges (`LEGITIMATE`, `INTERNAL`, `SUSPICIOUS`, `MALICIOUS`, `INFO`) assigned to specific Subnets or ASNs.
9. **`rollup_signatures`:** Optional User-Agent and client signature dimensions linked to subnet rollups for distributed fingerprinting.
10. **`network_entity` & `network_entity_match`:** Normalized directory of enriched client IPs and subnets with ASN, geolocation, threat classification, and cross-references to matched threat intelligence ranges.
11. **`intel_source` & `intel_range`:** Threat intelligence directory containing verified CIDR blocks from search engine bots, commercial AI scrapers, and Tor exit relays.
12. **`asn_info`:** Autonomous System catalog caching organization names and datacenter / hosting provider classifications.
13. **`crawler_feeds` & `bot_ip_ranges`:** Automatic synchronization catalog for official bot feeds (Googlebot, Bingbot, OpenAI, Anthropic) with versioning and orphan pruning.
14. **`poll_event_log`:** Diagnostic audit trail tracking background ingestion cycles (`blocked_events_ingested`, `marked_events_ingested`, `events_ingested`), communication latency, warnings, and recovery gap-fills.

---

## REST & Forensics API

| Endpoint | Method | Parameters | Description |
|---|---|---|---|
| `/api/v1/fleet` | `GET` | - | Fleet overview: online status, 24h request totals, active valves. |
| `/api/v1/valves` | `GET` | `serverId` (optional) | Query live and persisted Valve runtime configurations across the fleet or filtered by node. |
| `/api/v1/valves/{valveName}` | `GET` | `serverId` (required) | Query detailed runtime configuration for a specific named Valve on a specific server node. |
| `/api/v1/rollups/subnets` | `GET` | `servers`, `valves`, `hours`, `subnetQuery`, `asn`, `clientTypes`, `limit`, `offset` | Retrieve persistent subnet rollups with botnet heuristics. |
| `/api/v1/rollups/subnets/aggregate` | `POST` | `hours` | On-demand trigger to calculate completed rollup buckets. |
| `/api/v1/reputation/blocked-ips` | `GET` | `hours`, `format` (`json` or `text`) | Export blocked IP addresses as a plain text blocklist for firewall ingest or JSON. |
| `/api/v1/poll-log` | `GET` | `beforeId`, `status`, `serverId`, `limit` | Paginated query of polling audit log entries. |
