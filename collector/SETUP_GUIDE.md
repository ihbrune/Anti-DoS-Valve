# Anti-DoS Collector: Setup, Deployment & Operations Guide

This guide is designed for **DevOps Engineers, Site Reliability Engineers (SRE), and System Administrators** installing, deploying, configuring, and operating the **Anti-DoS Collector** in production environments.

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
java -jar collector/target/anti-dos-collector-1.7.4.jar demo
# Or with a larger fleet (e.g. 3 instances per server type = 9 total servers A, B, C):
java -jar collector/target/anti-dos-collector-1.7.4.jar demo 3

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
Produces the executable Spring Boot JAR in `collector/target/anti-dos-collector-1.7.4.jar`.

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
java -jar collector/target/anti-dos-collector-1.7.4.jar test-endpoint \
  --url "http://localhost:8080/antidos-status" \
  --token "secretToken1" \
  --name "Web-Node-1"
```

### 4. Run the Collector
```bash
java -jar collector/target/anti-dos-collector-1.7.4.jar
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
    url: "jdbc:sqlite:/var/lib/antidos/antidos-collector.db?busy_timeout=10000"

collector:
  poll-interval-seconds: 15
  parallel-fleet-polling: true
  retention-days: 30
  poll-log-retention-days: 1
  entity-retention-days: 60
  rollup-window-minutes: 60
  rollup-retention-days: 180
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
sudo cp collector/target/anti-dos-collector-1.7.4.jar /opt/antidos-collector/anti-dos-collector.jar
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
    url: "jdbc:sqlite:/var/lib/antidos/antidos-collector.db?busy_timeout=10000"
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

## Data Retention & Entity Hygiene Strategy

Automated background schedules execute daily at **03:00 AM** and **03:30 AM**:
1. **Telemetry & Incidents (`retention-days: 30`):** Prunes raw `client_events` and `slot_snapshots` older than 30 days.
2. **Audit Diagnostics (`poll-log-retention-days: 1`):** Purges diagnostic polling event logs older than 24 hours.
3. **Orphan Entity Cleanup (`entity-retention-days: 60`):** Deletes inactive `network_entity` records with zero remaining associated events.
4. **Persistent Subnet Rollups (`rollup-retention-days: 180`):** Retains aggregated `/24` and `/64` subnet traffic buckets for 180 days.

---

## Relational Database Schema & Data Model

The database separates real-time transient telemetry, persistent subnet aggregations, and normalized network intelligence:

```
 +------------------------+             +------------------------+
 |  endpoint_heartbeats   |             |     poll_event_log     |
 +------------------------+             +------------------------+
 | PK server_id           |<- - - - - - | id (PK)                |
 |    url                 |  (logical)  | server_id              |
 |    is_online           |             | status, poll_time      |
 +-----------+------------+             +------------------------+
             | 1
             | (logical)
             | N
 +-----------v------------+
 |     slot_snapshots     |
 +------------------------+
 | PK id                  |
 | UQ (server, valve, key)|
 +-----------+------------+
             | 1
             | (logical)
             | N
 +-----------v---------------------------------------------------+
 |                         client_events                         |
 +---------------------------------------------------------------+
 | PK id                                                         |
 | UQ (server_id, valve_name, slot_key, client_key)              |
 |    request_count, retained_count, is_locked, status           |
 |    ip_version, cidr_prefix, ip_v4_start/end, ip_v6_start/end   |
 |    subnet_group, asn, as_org, country_code, client_type       |
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
 |    total/active/blocked_requests  |     |    subnet_group     |
 |    distinct/min/max_clients       |     |    asn, as_org      |
 |    asn, as_org, client_type       |     |    client_type      |
 +-----------+-----------------------+     +----------+----------+
             | 1                                      | 1
             |                                        |
             | N                                      | N
 +-----------v------------+                +----------v----------+
 |   rollup_signatures    |                | network_entity_match|
 +------------------------+                +---------------------+
 | PK id                  |                | PK id               |
 | FK rollup_id           |                | FK entity_id        |
 |    ua_id, req_count    |                | FK range_id         |
 +------------------------+                +----------+----------+
                                                      | N
                                                      |
                                                      | 1
 +---------------------+                   +----------v----------+
 |      asn_info       |                   |     intel_range     |
 +---------------------+                   +---------------------+
 | PK asn              |                   | PK id               |
 |    as_org           |                   | FK source_key       |
 |    category         |                   |    cidr, category   |
 +---------------------+                   +----------+----------+
                                                      | N
                                                      |
 +------------------------+                           | 1
 |     crawler_feeds      |                +----------v----------+
 +------------------------+                |    intel_source     |
 | PK id                  |                +---------------------+
 |    feed_name, status   |                | PK source_key       |
 |    etag, last_synced_at|                |    display_name     |
 +-----------+------------+                |    category, feed_url|
             | 1                           +---------------------+
             |
             | N
 +-----------v------------+
 |     bot_ip_ranges      |
 +------------------------+
 | PK id                  |
 | FK feed_id             |
 |    bot_name, cidr      |
 |    ip_v4/v6_start/end  |
 +------------------------+
```

### Key Tables Overview
1. **`endpoint_heartbeats`:** Real-time health, latency, online/offline status, and valve discovery per monitored server node.
2. **`slot_snapshots`:** Completed and active 1-minute time slots per server and valve instance with total request and client counts.
3. **`client_events`:** Granular rate-limit events (both blocked attacks and tracked active clients) with numeric IPv4/IPv6 boundaries (`ip_v4_start`, `ip_v4_end`) for sub-millisecond range lookups.
4. **`client_subnet_rollups`:** Persistent 1-hour time-bucket aggregations per `/24` (IPv4) or `/64` (IPv6) subnet partition with distinct client tracking, request percentiles, and botnet heuristic metrics.
5. **`rollup_signatures`:** Optional User-Agent and client signature dimensions linked to subnet rollups for distributed fingerprinting.
6. **`network_entity`:** Normalized directory of enriched client IPs and subnets with ASN, geolocation, threat classification, and first/last seen timestamps.
7. **`network_entity_match`:** Cross-reference junction table linking detected network entities to specific matched threat intelligence ranges.
8. **`intel_source` & `intel_range`:** Threat intelligence directory containing verified CIDR blocks from search engine bots, commercial AI scrapers, and Tor exit relays.
9. **`asn_info`:** Autonomous System catalog caching organization names and datacenter / hosting provider classifications.
10. **`crawler_feeds` & `bot_ip_ranges`:** Automatic synchronization catalog for official bot feeds (Googlebot, Bingbot, OpenAI, Anthropic) with versioning and orphan pruning.
11. **`poll_event_log`:** Diagnostic audit trail tracking background ingestion cycles, communication latency, warnings, and recovery gap-fills.

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
