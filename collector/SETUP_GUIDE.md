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
java -jar collector/target/anti-dos-collector-2.1.0.jar demo
# Or with a larger fleet (e.g. 3 instances per server type = 9 total servers A, B, C):
java -jar collector/target/anti-dos-collector-2.1.0.jar demo 3

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
Produces the executable Spring Boot JAR in `collector/target/anti-dos-collector-2.1.0.jar`.

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

### 3. Verify an Endpoint or Generate Access Tokens via CLI
```bash
# Test a remote Valve endpoint
java -jar collector/target/anti-dos-collector-2.1.0.jar test-endpoint \
  --url "http://localhost:8080/antidos-status" \
  --token "secretToken1" \
  --name "Web-Node-1"

# Generate a cryptographically random hex token (default 32 bytes = 64 hex chars)
java -jar collector/target/anti-dos-collector-2.1.0.jar generate-token \
  --name "soc-operator" \
  --role OPERATOR
```

### 4. Run the Collector
```bash
java -jar collector/target/anti-dos-collector-2.1.0.jar
```
Dashboard available at **`http://localhost:8090`**.

---

## Operational Modes (`FULL`, `HEADLESS`, `OPERATOR`, `VIEWER`)

The Collector supports four operational modes controlled via `collector.mode` (environment variable `COLLECTOR_MODE`) or CLI shortcuts:

| Mode | Embedded Web Server / UI | Background Workers | Database Writes Allowed | Intended Use Case |
|---|---|---|---|---|
| **`FULL`** (default) | Enabled (`http://localhost:8090`) | Enabled | Full Read/Write (`WAL`) | Standard single-host deployment combining polling, enrichment, mitigation, and UI. |
| **`HEADLESS`** | **Disabled** (`WebApplicationType.NONE`, `keep-alive=true`) | Enabled | Full Read/Write (`WAL`) | Runs on isolated backend servers with no exposed HTTP port; collects telemetry and synchronizes dynamic rules onto Valves. |
| **`OPERATOR`** | Enabled (analyst UI, notes, reports, dynamic rules) | **Disabled** | **Scoped Read/Write** (notes, daily reports, dynamic mitigation rules only) | Analyst and operator interface: view telemetry, edit network notes, comment/regenerate daily reports, and create/revoke dynamic CIDR blocks while leaving background polling, system maintenance (`VACUUM`, retention, valve deletion), and auto-mitigation configuration disabled. |
| **`VIEWER`** | Enabled (strict read-only UI & REST GET APIs) | **Disabled** | **Disabled** (zero DB writes) | Safe forensic inspection of a copied `.db` snapshot, read-only volume, or remote database without mutating data or polling endpoints. |

### Quick CLI Launch Examples
```bash
# Start without web UI/server on an isolated server (or set COLLECTOR_MODE=HEADLESS)
java -jar collector/target/anti-dos-collector-*.jar headless

# Open an existing database in OPERATOR mode (notes, daily reports, and dynamic blocks enabled)
java -jar collector/target/anti-dos-collector-*.jar operator /path/to/antidos-collector.db

# Open a copied SQLite snapshot in strict read-only VIEWER mode
java -jar collector/target/anti-dos-collector-*.jar viewer /path/to/copied-antidos-collector.db

# Or configure via property / environment variable:
COLLECTOR_MODE=VIEWER java -jar collector/target/anti-dos-collector-*.jar \
  --spring.datasource.url="jdbc:sqlite:/path/to/snapshot.db?busy_timeout=60000"
```

### Guardrails in `VIEWER` and `OPERATOR` Modes
* **Existing Database Verification & Flyway:** Both `VIEWER` and `OPERATOR` verify that a file-based SQLite database already exists (never creating missing directories or empty `.db` files) and disable Flyway startup migrations (`spring.flyway.enabled=false`) as well as startup event repair and autonomous mitigation (`collector.auto-mitigation.enabled=false`). Set `collector.viewer-migrate-on-startup=true` only if you intentionally need Flyway to run on startup.
* **Strict Read-Only Enforcement (`VIEWER`):** For SQLite, `VIEWER` initializes connections with `PRAGMA query_only=ON;` instead of `PRAGMA journal_mode=WAL;`; for PostgreSQL, HikariCP marks connections `readOnly=true`. All scheduled tasks, background workers, and mutating `POST`/`DELETE` endpoints reject writes with HTTP `403 Forbidden`.
* **Scoped Operator Access (`OPERATOR`):** Connects in normal read/write mode (`WAL` on SQLite) while keeping all background pollers, enrichment, rollup schedulers, and system/admin actions (`VACUUM`, retention cleanup, rollup catch-up, crawler sync, valve deletion, auto-mitigation settings, direct fleet sync) disabled (`HTTP 403 Forbidden`). Dynamic rules created or revoked in `OPERATOR` mode are persisted in `mitigation_rules` and pushed to edge Valves by the `HEADLESS` (or `FULL`) collector during its regular polling cycle.
* **Mutual Exclusivity:** `HEADLESS`, `OPERATOR`, and `VIEWER` cannot be combined with `demo` mode.

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

  browser-reference:
    enabled: true
    safari-versions:
      - "26.2 STP"
      - "26.1"
      - "26.0"
      - "18.2"
      - "17.6"

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
sudo cp collector/target/anti-dos-collector-2.1.0.jar /opt/antidos-collector/anti-dos-collector.jar
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
5. **Tiered Subnet Rollup Compaction (`low-activity-rollup-retention-days: 7`, `low-activity-rollup-max-requests: 5`):**
   - **Tier 1 (Benign Long-Tail):** Rollups with zero security incidents (`blocked_requests = 0 AND marked_requests = 0`) and minimal request volume (`total_requests <= 5`) are purged after 7 days. This eliminates ~83% of storage bloat in `client_subnet_rollups`.
   - **Tier 2 (Security Incidents & Significant Traffic, `rollup-retention-days: 30`):** All rollups with blocked requests, marked requests, or significant volume are retained for the full 30 days (or 180 days in production) for rolling baselines and forensic investigation.
6. **SQLite Storage Compaction (`auto-vacuum-enabled: true`, `vacuum-threshold-bytes: 52428800`):** Automatically compacts SQLite standalone database files (`VACUUM`) during nightly retention cleanup if reclaimable freelist space exceeds 50 MB. Can also be triggered on demand via the System Status UI.

---

## Active Fleet Mitigation & Autonomous Defense Setup

The Anti-DoS ecosystem combines high-performance edge rate-limiting in Apache Tomcat (`AntiDoSValve`) with central telemetry aggregation, threat analysis, and automated fleet-wide mitigation (`AntiDoSCollector`).

This section explains the end-to-end architecture, configuration touchpoints, fail-safe security guardrails, and rollout procedures for system administrators and SRE teams.

---

### 1. Holistic Architecture & Component Interplay

The interaction between Tomcat Valves and the Collector is decoupled and asynchronous:

```
 +-------------------------------------------------------------------------------+
 |                               APACHE TOMCAT                                   |
 |                                                                               |
 |   Incoming HTTP Requests                                                      |
 |            |                                                                  |
 |            v                                                                  |
 |   +-----------------------------------------------------------------------+   |
 |   | AntiDoSValve (Catalina Pipeline)                                      |   |
 |   |                                                                       |   |
 |   |  Step 1: Check alwaysAllowedIPs (Whitelisted IPs bypass all blocks)   |   |
 |   |  Step 2: Check Dynamic CIDR Registry (HTTP 429 if match & not expired)|   |
 |   |  Step 3: Check Dynamic UA Registry (Bypass if Auth / Valid Returning)  |   |
 |   |  Step 4: Evaluate Sliding-Window Rate Limits (Local IP / Subnet)     |   |
 |   +-----------------------------------------------------------------------+   |
 |            |                                              ^                   |
 |            | Telemetry                                    | Dynamic Blocks    |
 |            | (GET /antidos-status)                        | (POST /antidos-   |
 |            | Pull: every 15s                              |        mitigate)  |
 +------------|----------------------------------------------|-------------------+
              |                                              |
              v                                              |
 +-----------------------------------------------------------|-------------------+
 | ANTI-DOS COLLECTOR                                        |                   |
 |                                                           |                   |
 |   +-------------------------------------------------------+---------------+   |
 |   | Mitigation Control Plane & AutoMitigationService                      |   |
 |   |                                                                       |   |
 |   |  * Scheduled Telemetry Evaluation (every 2m)                          |   |
 |   |  * Carpet Attack Detection (Multi-subnet ASN flood analysis)           |   |
 |   |  * 8 Deterministic Safety Guardrails (Zero auth, returning ratio, etc)|   |
 |   |  * In-Memory / Database Rule Management (system_settings dominance)   |   |
 |   |  * Browser Notifications (HTML5 Desktop & In-App Toast Alerts)        |   |
 |   |  * Webhook & Slack Alert Notifications (Async Non-Blocking HTTP POST) |   |
 |   +-----------------------------------------------------------------------+   |
 |            |                                                                  |
 |            v                                                                  |
 |   +-------------------------+      +--------------------------------------+   |
 |   | Relational Database     |      | Web UI: /mitigation                  |   |
 |   | (mitigation_rules,      |      | (Rule Batches, Deterrence Monitor,   |   |
 |   |  mitigation_audit_log,  |      |  Live Settings Toggles, Auditing)    |   |
 |   |  system_settings)       |      +--------------------------------------+   |
 |   +-------------------------+                                                 |
 +-------------------------------------------------------------------------------+
```

#### Decoupled Resilience Principles:
1. **Zero Runtime Overhead on Request Ingress:** The Valve executes in Tomcat's fast path without querying any database or network service. Dynamic CIDR matching uses an optimized, thread-safe in-memory radix trie.
2. **Collector Outage Isolation:** If the Collector is stopped, restarted, or partitioned by network issues, the Valves continue rate-limiting and enforcing active dynamic blocks until each block's bounded time-to-live (`expiresAt`) expires. No traffic is dropped due to Collector downtime.
3. **Graceful Valve Restarts:** If a Tomcat instance restarts, its volatile in-memory dynamic blocks are cleared. On the next 15-second polling cycle, the Collector detects the revision mismatch (`dynamicRulesRevision`) and automatically reconciles the active rule set.
4. **Selective Enforcement:** Nodes without `mitigationPassword` configured (e.g., upstream simulation or pure monitoring valves) remain untouched, continuing to capture raw baseline telemetry without dropping packets.

---

### 2. Configuration: What Goes Where?

Configuration is split cleanly between the protected Tomcat server and the central Collector service.

#### A. Valve Configuration (`conf/server.xml`)

To enable dynamic mitigation on a Tomcat Valve, configure `mitigationPassword` (minimum 10 characters). If omitted, dynamic mitigation endpoints are disabled (`HTTP 403 Forbidden`).

```xml
<Valve className="org.henbru.antidos.AntiDoSValve"
       statusUri="/antidos-status"
       statusSecretToken="statusSecretToken1"
       mitigationUri="/antidos-mitigate"
       mitigationPassword="strongMitigationSecretToken123"
       mitigationMinPrefixV4="16"
       mitigationMinPrefixV6="32"
       mitigationMaxTtlSeconds="86400"
       mitigationMaxActiveBlocks="500"
       alwaysAllowedIPs="127.0.0.1,10.0.0.0/8,192.168.1.0/24"
       defaultPeriodSeconds="60"
       defaultAllowedRequests="100" />
```

| Parameter (`server.xml`) | Default | Description |
|---|---|---|
| `mitigationPassword` | *null* (disabled) | Shared write secret required to authenticate dynamic block push, extend, and revoke commands via `POST /antidos-mitigate`. Must be at least 10 characters. |
| `mitigationUri` | `/antidos-mitigate` | URL path exposing the dynamic mitigation control endpoint. |
| `mitigationMinPrefixV4` | `16` | Minimum CIDR prefix length allowed for IPv4 dynamic blocks. Rejects overly broad blocks (e.g. `/8` or `/0`) with `HTTP 400 Bad Request`. |
| `mitigationMinPrefixV6` | `32` | Minimum CIDR prefix length allowed for IPv6 dynamic blocks. |
| `mitigationMaxTtlSeconds` | `86400` (24h) | Hard upper ceiling for block durations. Any requested TTL exceeding this value is clamped to prevent permanent lockouts. |
| `mitigationMaxActiveBlocks` | `500` | Maximum number of concurrent dynamic CIDR blocks stored in RAM, protecting Tomcat against memory exhaustion. |

---

#### B. Collector Configuration (`collector-config.yaml`)

The Collector requires credentials to communicate with the Valve's mitigation endpoint and configuration for the autonomous defense engine:

```yaml
collector:
  # Global write token (matches 'mitigationPassword' on target Valves)
  mitigation-token: "strongMitigationSecretToken123"

  # Default duration for newly created dynamic blocks in minutes (default: 60)
  default-mitigation-ttl-minutes: 60

  # Autonomous Defense Engine (Auto-Mitigation)
  auto-mitigation:
    enabled: false                # Master switch (default: false for safe initial deployment)
    dry-run: true                 # Simulation mode (audits decisions without altering Valve rules)
    carpet-min-subnets: 3         # Minimum active subnets per ASN to detect carpet attacks
    carpet-min-requests: 5000     # Minimum aggregate requests across the ASN in the lookback window
    carpet-window-hours: 1        # Lookback evaluation window in hours (default: 1 hour)
    protected-asns: "8075,16509,14618,15169,13335" # Protected ASNs exempt from auto-mitigation (Microsoft, AWS, Google, Cloudflare)
    max-returning-ratio-pct: 5.0  # Max returning visitor ratio allowed for auto-blocking (collateral protection)
    max-active-rules: 50          # Circuit breaker cap across the fleet
    default-ttl-minutes: 60       # Default TTL for autonomous blocks
    auto-extend-persistent: true  # Automatically extend persistent attackers near expiration
    max-extension-hours: 12       # Maximum cumulative lifetime cap

  endpoints:
    - name: "Edge-Node-01"
      url: "http://10.0.1.10:8080/antidos-status"
      token: "statusSecretToken1"
      # Optional: per-server override if different from global mitigation-token
      # mitigation-token: "edgeSpecificSecretToken"
      # mitigation-url: "http://10.0.1.10:8080/antidos-mitigate"
```

##### Token Resolution Cascade:
When pushing mitigation commands to an endpoint, the Collector resolves credentials in this order:
1. `endpoints[].mitigation-token` (explicit per-server override)
2. `collector.mitigation-token` (global shared write token)
3. `endpoints[].token` (fallback to the server's status token)

---

#### C. Runtime Dominance & Database Settings (`system_settings`)

To allow operations teams to respond quickly to live attacks without modifying YAML files or restarting the Collector, settings follow a strict **Database-over-File** precedence hierarchy:

```
  Deployment Baseline                 Runtime Overrides                  Active Engine
+----------------------+           +--------------------+           +----------------------+
| collector-config.yaml| --------> | Database Table:    | --------> | AutoMitigationService|
| (or ENV variables)   | (Fallback)| system_settings    | (Dominates| (Evaluates DB first) |
+----------------------+           +--------------------+           +----------------------+
```

1. **Deployment Baseline:** Configuration files define startup defaults, ideal for GitOps and Infrastructure-as-Code pipelines.
2. **Runtime Overrides via UI:** Changes made in the `/mitigation` dashboard (e.g. Master Switch, Dry-Run toggle, threshold adjustments) are immediately saved to the `system_settings` relational table.
3. **Execution Dominance:** The `AutoMitigationService` reads from `system_settings` on every scheduled cycle. If a parameter exists in the database, it overrides the YAML configuration.
4. **Clean Reset:** Clicking **Reset to Defaults** in the UI removes database overrides, cleanly reverting all parameters back to the `collector-config.yaml` values.

---

### 3. Deterministic Safety Architecture

Automated blocking systems carry the risk of collateral damage if misconfigured. The Anti-DoS Autonomous Defense Engine is built around **7 deterministic safety guardrails** to ensure legitimate traffic is never disrupted:

```
+-----------------------------------------------------------------------------------+
|                        8 DETERMINISTIC SAFETY GUARDRAILS                          |
+-----------------------------------------------------------------------------------+
| 1. Whitelist Precedence    | alwaysAllowedIPs evaluated BEFORE dynamic blocks.     |
| 2. Zero Auth Sessions      | ANY authenticated request (authenticated > 0) exempts|
|                            | the subnet partition from autonomous mitigation.     |
| 3. Returning Visitor Ratio | Subnets with cookie returning ratio > max_ratio (5%) |
|                            | are protected against auto-blocking.                 |
| 4. Crawler & RFC1918 Bypas | Verified bots (Google, Bing) and private nets spared.|
| 5. Prefix Width Limits     | Hard limits (/16-/32 IPv4, /32-/128 IPv6).           |
| 6. Self-Expiring TTL       | In-memory leases with automatic eviction. No residue.|
| 7. Fleet Circuit Breaker   | Hard limit on active auto-rules (default: 50).        |
| 8. Fleet Emergency Flush   | One-click panic button immediately wipes all blocks. |
+-----------------------------------------------------------------------------------+
```

1. **`alwaysAllowedIPs` Ingress Precedence:**
   - Evaluated *before* dynamic CIDR checks in the Valve's Catalina request pipeline.
   - Internal load balancers, health checks, VPN exit nodes, payment provider callbacks, and corporate office ranges can **never** be locked out by dynamic rules.

2. **Zero Authenticated Sessions Safeguard:**
   - The Valve tracks user sessions via `authTrackingEnabled="true"` and login paths (`authLoginPaths`).
   - If even **a single authenticated request** (`authenticated_requests > 0`) is observed from a subnet in the telemetry window, that subnet is strictly disqualified from autonomous mitigation and flagged for operator review.

3. **Returning Visitor Ratio Firewall (`max_returning_ratio_pct`):**
   - Legitimate user pools (residential broadband providers, university campuses, mobile carrier CGNATs) accumulate returning cookies over time (`visitorCookieEnabled="true"`).
   - Distributed botnet carpet scrapers use disposable HTTP clients with near-zero cookie retention.
   - The engine computes:
     $$\text{Returning Ratio} = \frac{\text{Returning Requests}}{\text{Total Requests}} \times 100$$
   - If the ratio exceeds `max_returning_ratio_pct` (default: 5.0%), autonomous blocking is aborted to protect genuine human users.

4. **Crawler Feed & RFC 1918 Exclusions:**
   - IP ranges matching verified search engines (Googlebot, Bingbot) and private networks (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and loopback) are automatically excluded.

5. **CIDR Prefix Boundaries:**
   - Enforced by both the Collector and the Valve's `mitigationMinPrefixV4` / `mitigationMinPrefixV6`.
   - Prevents catastrophic over-blocking (e.g. accidental submission of `/8`, `/0`, or carrier supernets).

6. **Bounded Self-Expiring In-Memory Leases:**
   - Every block carries a strict `expiresAt` timestamp and is capped by `mitigationMaxTtlSeconds` (default: 24 hours).
   - If the Collector crashes, loses network connectivity, or is decommissioned, all dynamic blocks automatically expire and vanish from the Valve's RAM. No permanent or stale firewall rules are left behind.

7. **Fleet-Wide Circuit Breaker Cap (`maxActiveRules`):**
   - Restricts the total number of simultaneous autonomous blocks across the fleet (default: 50).
   - Prevents cascading runaway blocking during massive, multi-vector DDoS events and alerts administrators to intervene manually.

8. **Fleet Emergency Flush (Instant Reversion Panic Button):**
   - If an unexpected block or operator configuration mistake occurs, the `/mitigation` dashboard provides an instant **🚨 Emergency Flush (Revoke All)** action.
   - When confirmed, all active rules are marked `REVOKED` in the database, audited as `EMERGENCY_FLUSH`, and an empty block set (`action=replace`, `blocks=""`) is pushed immediately to all Valves across the entire fleet—clearing every in-memory dynamic block in milliseconds and instantly reopening traffic.

---

### 4. Administrator Rollout Playbook: In 3 Steps

Deploying autonomous defense follows a structured verification path:

#### Step 1: Baseline Verification
1. Add `mitigationPassword` to Tomcat's `server.xml` and restart Tomcat.
2. Add `mitigation-token` to `collector-config.yaml` and restart the Collector.
3. Open **Mitigation (`/mitigation`)** in the Collector dashboard. Verify that the **Targeted Valves** counter reflects your mitigation-enabled instances.
4. Perform a manual single IP test block (e.g. 5-minute TTL on a test IP) and verify immediate HTTP 429 response. Revoke the test block.

#### Step 2: Simulation Mode (Dry-Run Auditing)
1. In `collector-config.yaml` (or via the UI drawer in `/mitigation`), set:
   * `enabled: true`
   * `dry-run: true`
2. Subscribe to **Browser Notifications** by clicking the bell icon (`🔔`) in the top navigation bar and granting browser notification permissions.
3. Allow the system to run through peak traffic and overnight hours.
4. Inspect the **Mitigation Audit Trail** (`/mitigation`). Review all entries marked `AUTO_WOULD_BLOCK` and `AUTO_WOULD_EXTEND` to verify that detected ASNs and subnets represent genuine attacks and that no legitimate user pools are targeted.

#### Step 3: Activation of Live Autonomous Defense
1. Once satisfied with the simulation results, open `/mitigation` and toggle **Dry-Run Mode** to **Off**.
2. The Autonomous Defense Engine will now push live dynamic blocks to the Valves whenever a qualifying attack occurs.
3. Active blocks appear under **Active Rule Batches** and **Deterrence Monitor**, where their deterrence state (`OBSERVING`, `PERSISTENT`, `DETERRED`) can be tracked in real-time.
4. In the event of an unintended block or emergency, click **🚨 Emergency Flush (Revoke All)** in the active mitigations card to immediately clear all dynamic blocks across the entire fleet in milliseconds.

---

### 5. Webhook Alerting (Slack, Teams, Discord, Generic SIEM)

The Collector includes a built-in asynchronous notification dispatcher (`AlertNotificationService`) that dispatches real-time security alerts to external collaboration channels and monitoring pipelines:

* **Zero Third-Party SDK Dependencies:** Built natively using Java 21 `HttpClient` and non-blocking asynchronous dispatch (`sendAsync`). Even if the remote webhook endpoint is slow or unreachable, Collector polling and mitigation pipelines remain completely non-blocking.
* **Universal Standard Format:** Payloads include standard Markdown / mrkdwn formatted `text` as well as structured JSON metadata (`event`, `asn`, `subnets`, `batchId`, `reason`, `timestamp`). This format works natively out-of-the-box with:
  * **Slack:** Via standard Incoming Webhooks.
  * **Mattermost & Rocket.Chat:** 100% Slack-compatible.
  * **Discord:** By appending `/slack` to standard Discord webhook URLs.
  * **Microsoft Teams:** Via Incoming Webhooks or modern Power Automate / Workflows.
  * **SIEM / Generic Receivers:** n8n, Zapier, Splunk, Elastic, Alertmanager.
* **Sensitive Token Masking:** Target URLs with private tokens (such as Slack webhook secrets) are automatically masked in log files (e.g. `https://hooks.slack.com/services/T00000000/...`).
* **Live In-App Testing & Overrides:** Webhook URL and notification switches can be configured live in the `/mitigation` dashboard. Click **Send Test Notification** to immediately verify delivery with instantaneous HTTP status feedback.

---

## Configuration Reference (`application.yaml` & `collector-config.yaml`)

All parameters can be configured via `collector-config.yaml` or overridden via environment variables:

### Core Polling & Retention Settings

| YAML Property (`collector.*`) | Environment Variable | Default | Description |
|---|---|---|---|
| `config-file` | `COLLECTOR_CONFIG_FILE` | `collector-config.yaml` | Name or path of the endpoint configuration file. |
| `poll-interval-seconds` | `COLLECTOR_POLL_INTERVAL_SECONDS` | `15` | Default polling interval in seconds across all monitored endpoints. |
| `parallel-fleet-polling` | `COLLECTOR_PARALLEL_FLEET_POLLING` | `true` | Concurrently poll fleet endpoints in parallel using Java 21 Virtual Threads. |
| `slow-poll-threshold-ms` | `COLLECTOR_SLOW_POLL_THRESHOLD_MS` | `1000` | Endpoint response time threshold in ms before triggering a `WARNING` poll log entry. |
| `max-catch-up-slots-per-poll` | `COLLECTOR_MAX_CATCH_UP_SLOTS_PER_POLL` | `2` | Maximum missed slots a valve is permitted to backfill per poll cycle to prevent request avalanches on lagging servers. |
| `max-catch-up-lag-slots` | `COLLECTOR_MAX_CATCH_UP_LAG_SLOTS` | `6` | Maximum backlog horizon before ancient missed slots are safely dropped during recovery. |
| `endpoint-poll-timeout-ms` | `COLLECTOR_ENDPOINT_POLL_TIMEOUT_MS` | `25000` | Hard deadline in ms for polling all valves on a single endpoint node before skipping remaining valves. |
| `host-concurrency-timeout-seconds` | `COLLECTOR_HOST_CONCURRENCY_TIMEOUT_SECONDS` | `15` | Maximum wait time in seconds for the host-level semaphore ensuring at most 1 active request per host. |
| `retention-days` | `COLLECTOR_RETENTION_DAYS` | `30` | Retention horizon (in days) for security incidents (`BLOCKED`/`MARKED` events) and completed slot snapshots. |
| `active-event-retention-hours` | `COLLECTOR_ACTIVE_EVENT_RETENTION_HOURS` | `24` | Short-term retention (in hours) for high-volume benign `ACTIVE` client events. |
| `active-event-cleanup-cron` | `COLLECTOR_ACTIVE_EVENT_CLEANUP_CRON` | `0 15 * * * *` | Cron schedule for the hourly purge of expired `ACTIVE` events. |
| `poll-log-retention-days` | `COLLECTOR_POLL_LOG_RETENTION_DAYS` | `1` | Retention period (in days) for the polling audit trail (`poll_event_log`). |
| `entity-retention-days` | `COLLECTOR_ENTITY_RETENTION_DAYS` | `60` | Retention period (in days) for unreferenced/orphan network entities. |

### Subnet Rollup & Tiered Compaction Settings

| YAML Property (`collector.*`) | Environment Variable | Default | Description |
|---|---|---|---|
| `rollup-enabled` | `COLLECTOR_ROLLUP_ENABLED` | `true` | Enables scheduled aggregation of client events into subnet time buckets. |
| `rollup-window-minutes` | `COLLECTOR_ROLLUP_WINDOW_MINUTES` | `60` | Duration of each rollup bucket in minutes (typically 15 or 60). |
| `rollup-cron` | `COLLECTOR_ROLLUP_CRON` | `0 */15 * * * *` | Cron schedule triggering the rollup aggregation catch-up job. |
| `rollup-retention-days` | `COLLECTOR_ROLLUP_RETENTION_DAYS` | `30` | Full retention horizon (in days) for security incident rollups and substantial traffic. |
| `low-activity-rollup-retention-days` | `COLLECTOR_LOW_ACTIVITY_ROLLUP_RETENTION_DAYS` | `7` | Retention horizon (in days) for benign long-tail rollups with zero blocks and minimal requests. |
| `low-activity-rollup-max-requests` | `COLLECTOR_LOW_ACTIVITY_ROLLUP_MAX_REQUESTS` | `5` | Request count threshold (inclusive) below which incident-free rollups qualify for Tier 1 7-day compaction. |

### Baseline Surge & Anomaly Detection

| YAML Property (`collector.*`) | Environment Variable | Default | Description |
|---|---|---|---|
| `surge-min-requests` | `COLLECTOR_SURGE_MIN_REQUESTS` | `1000` | De minimis 24-hour volume threshold (requests) required before a subnet can trigger a High Surge alert. |
| `surge-multiplier-alert` | `COLLECTOR_SURGE_MULTIPLIER_ALERT` | `5.0` | Multiplier above 30-day historical baseline required to trigger High Surge categorization. |

### Active Fleet Mitigation & Autonomous Defense

| YAML Property (`collector.*`) | Environment Variable | Default | Description |
|---|---|---|---|
| `mitigation-token` | `COLLECTOR_MITIGATION_TOKEN` | `null` | Shared write secret matching `mitigationPassword` on the target Valve(s) for pushing dynamic CIDR blocks (`POST`). Can also be overridden per endpoint via `endpoints[].mitigation-token` and `endpoints[].mitigation-url`. |
| `default-mitigation-ttl-minutes` | `COLLECTOR_DEFAULT_MITIGATION_TTL_MINUTES` | `60` | Default TTL duration (in minutes) for newly created dynamic CIDR blocks before they automatically self-expire. |
| `auto-mitigation.enabled` | `COLLECTOR_AUTO_MITIGATION_ENABLED` | `false` | Master switch for the Autonomous Defense Engine. |
| `auto-mitigation.dry-run` | `COLLECTOR_AUTO_MITIGATION_DRY_RUN` | `true` | Simulation mode: audits decisions as `AUTO_WOULD_BLOCK` and `AUTO_WOULD_EXTEND` in the mitigation audit trail without altering live Valve rules. |
| `auto-mitigation.carpet-min-subnets` | `COLLECTOR_AUTO_MITIGATION_CARPET_MIN_SUBNETS` | `3` | Minimum active `/24` or `/64` subnets belonging to a single ASN required to qualify as a horizontal carpet attack. |
| `auto-mitigation.carpet-min-requests` | `COLLECTOR_AUTO_MITIGATION_CARPET_MIN_REQUESTS` | `5000` | Aggregate request volume threshold across the attacking ASN subnets within the lookback window. |
| `auto-mitigation.carpet-min-requests-per-subnet` | `COLLECTOR_AUTO_MITIGATION_CARPET_MIN_REQUESTS_PER_SUBNET` | `20` | Minimum requests a single subnet must have produced within the lookback window to be auto-blocked. Rotating residential proxy botnets send only a handful of requests per `/24` before moving on; blocking such subnets afterwards has no effect but consumes rule capacity. `0` disables the filter. |
| `auto-mitigation.carpet-window-hours` | `COLLECTOR_AUTO_MITIGATION_CARPET_WINDOW_HOURS` | `1` | Evaluation lookback window (in hours) across persistent subnet rollups for carpet attack detection. |
| `auto-mitigation.protected-asns` | `COLLECTOR_AUTO_MITIGATION_PROTECTED_ASNS` | `8075,16509,14618,15169,13335` | Comma-separated list of protected ASNs (e.g. Microsoft Azure, Amazon AWS, Google Cloud, Cloudflare) exempt from autonomous ASN-wide blocking. |
| `auto-mitigation.max-returning-ratio-pct` | `COLLECTOR_AUTO_MITIGATION_MAX_RETURNING_RATIO_PCT` | `5.0` | Maximum returning visitor cookie ratio (%) permitted for autonomous blocking. Protects legitimate residential ISP and mobile carrier CGNAT pools from collateral blocks. |
| `auto-mitigation.max-authenticated-requests` | `COLLECTOR_AUTO_MITIGATION_MAX_AUTHENTICATED_REQUESTS` | `0` | Fixed maximum count of authenticated requests permitted across an ASN within the lookback window to qualify as a carpet attack candidate. Subnets with authenticated requests are never blocked. |
| `auto-mitigation.max-active-rules` | `COLLECTOR_AUTO_MITIGATION_MAX_ACTIVE_RULES` | `50` | Circuit breaker cap limiting the maximum number of concurrent autonomous dynamic rules across the fleet. Capacity is allocated by priority (highest per-subnet request volume first). When the cap is reached, autonomous rules that have not blocked a single request since activation (10-minute observation phase elapsed) are released to make room for stronger candidates. |
| `auto-mitigation.default-ttl-minutes` | `COLLECTOR_AUTO_MITIGATION_DEFAULT_TTL_MINUTES` | `60` | Initial block lease duration (in minutes) assigned to autonomous dynamic CIDR blocks. |
| `auto-mitigation.auto-extend-persistent` | `COLLECTOR_AUTO_MITIGATION_AUTO_EXTEND_PERSISTENT` | `true` | Proactively extends persistent attackers (`PERSISTENT` deterrence state) near expiration. |
| `auto-mitigation.max-extension-hours` | `COLLECTOR_AUTO_MITIGATION_MAX_EXTENSION_HOURS` | `12` | Maximum cumulative lifetime cap (in hours) permitted for an autonomously extended rule. |

### Alerting & Webhook Notifications (`collector.notification.*`)

| YAML Property (`collector.*`) | Environment Variable | Default | Description |
|---|---|---|---|
| `notification.enabled` | `COLLECTOR_NOTIFICATION_ENABLED` | `false` | Master switch for dispatching outgoing HTTP webhook alert notifications. |
| `notification.webhook-url` | `COLLECTOR_NOTIFICATION_WEBHOOK_URL` | `null` | Target Webhook URL (Slack Incoming Webhook, Microsoft Teams Workflow, Discord `/slack`, Mattermost, or generic HTTP endpoint). |
| `notification.notify-on-dry-run` | `COLLECTOR_NOTIFICATION_NOTIFY_ON_DRY_RUN` | `true` | Send alert notifications when the Autonomous Defense Engine detects an attack in Simulation / Dry-Run mode. |
| `notification.notify-on-auto-block` | `COLLECTOR_NOTIFICATION_NOTIFY_ON_AUTO_BLOCK` | `true` | Send alert notifications when live dynamic CIDR blocks are pushed to the fleet. |
| `notification.notify-on-emergency-flush` | `COLLECTOR_NOTIFICATION_NOTIFY_ON_EMERGENCY_FLUSH` | `true` | Send alert notifications when an operator triggers a fleet-wide emergency flush. |
| `notification.notify-on-circuit-breaker` | `COLLECTOR_NOTIFICATION_NOTIFY_ON_CIRCUIT_BREAKER` | `true` | Send alert notifications when the concurrent auto-mitigation circuit breaker cap is reached. |

### SQLite Storage Maintenance & Compaction

| YAML Property (`collector.*`) | Environment Variable | Default | Description |
|---|---|---|---|
| `auto-vacuum-enabled` | `COLLECTOR_AUTO_VACUUM_ENABLED` | `true` | Automatically executes SQLite `VACUUM` during nightly maintenance if threshold is exceeded. |
| `vacuum-threshold-bytes` | `COLLECTOR_VACUUM_THRESHOLD_BYTES` | `52428800` (50 MB) | Reclaimable freelist space threshold in bytes before automatic vacuum is performed. |

### Operational Reporting

| YAML Property (`collector.*`) | Environment Variable | Default | Description |
|---|---|---|---|
| `report-enabled` | `COLLECTOR_REPORT_ENABLED` | `true` | Enables automatic nightly aggregation of operational reports into `daily_reports`. |
| `report-cron` | `COLLECTOR_REPORT_CRON` | `0 0 1 * * *` | Cron schedule (daily at 01:00 AM) compiling the operational markdown report. |

### IP Enrichment & Threat Intelligence (`collector.enrichment.*`)

| YAML Property | Environment Variable | Default | Description |
|---|---|---|---|
| `enabled` | `COLLECTOR_ENRICHMENT_ENABLED` | `true` | Enables asynchronous IP metadata enrichment (GeoIP, ASN, threat classification). |
| `ttl-days` | `COLLECTOR_ENRICHMENT_TTL_DAYS` | `30` | Metadata validity TTL in days; expired records are queued for re-resolution. |
| `asn-database-path` | - | `null` | Path to offline MMDB binary database for ASN lookups (DB-IP Lite or MaxMind). |
| `country-database-path` | - | `null` | Path to offline MMDB binary database for country lookups. |
| `custom-datacenter-asns-file` | - | `custom-datacenter-asns.txt` | Path to custom ASN classification overlay file. |
| `crawler-sync-enabled` | `COLLECTOR_CRAWLER_SYNC_ENABLED` | `true` | Enables automatic synchronization of official search engine and AI crawler IP ranges. |
| `crawler-sync-cron` | - | `0 0 4 * * *` | Daily sync cron schedule (04:00 AM). |
| `crawler-retry-cron` | - | `0 15 * * * *` | Hourly retry cron schedule for transient feed failures. |

### Authoritative Browser Version Intelligence (`collector.browser-reference.*`)

| YAML Property | Environment Variable | Default | Description |
|---|---|---|---|
| `enabled` | `COLLECTOR_BROWSER_REFERENCE_ENABLED` | `true` | Enables authoritative browser release ground truth for User-Agent analytics. |
| `chrome-api-url` | `COLLECTOR_BROWSER_CHROME_API_URL` | `https://versionhistory.googleapis.com/...` | Google Version History API endpoint for Chromium/Edge channels. |
| `firefox-api-url` | `COLLECTOR_BROWSER_FIREFOX_API_URL` | `https://product-details.mozilla.org/...` | Mozilla Product Details API endpoint for Firefox channels. |
| `safari-versions` | `COLLECTOR_BROWSER_SAFARI_VERSIONS` | `27.2 STP, 26.6, 26.1, 18.6, 17.6` | Configurable static version list for OS-bound Apple Safari releases. |
| `sync-interval-hours` | `COLLECTOR_BROWSER_SYNC_INTERVAL_HOURS` | `24` | Background synchronization interval (in hours) for upstream vendor feeds. |

### User-Agent 3-Pillar Heuristic & Memory (`collector.user-agent-heuristics.*`)

Thresholds defined here serve as baseline defaults and can be overridden live in the Web UI under `/analytics?tab=useragents` (persisted in `system_settings`; restricted to `FULL` mode):

| YAML Property | Default | Description |
|---|---|---|
| `internal-immunity-min-ratio-pct` | `5.0` | Minimum percentage of traffic from `PRIVATE_NETWORK` / `INTERNAL_NETWORK` to grant `IMMUNE_INTERNAL`. |
| `internal-immunity-min-requests` | `100` | Absolute internal request volume threshold granting `IMMUNE_INTERNAL` regardless of share. |
| `search-engine-immunity-min-ratio-pct` | `50.0` | Minimum share of verified `SEARCH_ENGINE` IP feed requests to grant `IMMUNE_SEARCH_ENGINE`. |
| `auth-immunity-min-sample-ratio-pct` | `1.0` | Minimum authenticated sample ratio (%) for Stage-0 `IMMUNE_AUTHENTICATED` exemption. |
| `auth-immunity-min-slot-ratio-pct` | `2.0` | Minimum slot-level `authenticated_count` share (%) for Stage-0 `IMMUNE_AUTHENTICATED` exemption. |
| `spread-min-requests` | `2500` | Pillar 1 minimum external unauthenticated request volume. |
| `spread-min-subnets` | `100` | Pillar 1 minimum distinct `/24` or `/64` subnets. |
| `spread-min-asns` | `20` | Pillar 1 minimum distinct Autonomous Systems. |
| `spread-max-avg-slot-requests` | `10.0` | Pillar 1 maximum average requests per slot identifying low-and-slow proxy distribution. |
| `spread-min-version-lag-majors` | `2` | Pillar 1 minimum browser major version lag (combined with ultra-spread scale). |
| `correlated-min-requests` | `2000` | Pillar 2 minimum external request volume for Guilt-by-Association evaluation. |
| `correlated-min-incident-ratio-pct` | `30.0` | Pillar 2 minimum rate-limiting incident event share (%). |
| `correlated-min-mitigated-asn-ratio-pct` | `40.0` | Pillar 2 minimum request share originating from ASNs with active or recent mitigations (%). |
| `correlated-min-ua-mismatch-ratio-pct` | `20.0` | Pillar 2 minimum request share with Visitor-Cookie User-Agent mismatches (%). |
| `datacenter-min-requests` | `1500` | Pillar 3 minimum external unauthenticated request volume. |
| `datacenter-min-ratio-pct` | `80.0` | Pillar 3 minimum request share from datacenter or Tor ASNs (%). |

### Endpoint Forensics & URL Hotspot Analysis (`collector.endpoint-analytics.*`)

| YAML Property (`collector.*`) | Environment Variable | Default | Description |
|---|---|---|---|
| `endpoint-analytics.default-exclude-automated` | `COLLECTOR_ENDPOINT_ANALYTICS_DEFAULT_EXCLUDE_AUTOMATED` | `true` | Default state of the 'Exclude Automated Background Services' toggle in dashboard & API. |
| `endpoint-analytics.default-exclude-internal` | `COLLECTOR_ENDPOINT_ANALYTICS_DEFAULT_EXCLUDE_INTERNAL` | `false` | Default state of the 'Exclude Internal Networks' toggle. |
| `endpoint-analytics.internal-threshold-percent` | `COLLECTOR_ENDPOINT_ANALYTICS_INTERNAL_THRESHOLD_PERCENT` | `90.0` | Traffic share (%) above which an endpoint is classified as internal. |
| `endpoint-analytics.excluded-prefixes` | - | `[/display, /api/room, /sync, /health, /healthz, /actuator, /ping, /status]` | Path prefixes excluded when automated service filtering is active (e.g. digital door displays, CMS sync, health probes). |

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
 |    subnet_profiles    |  | dim_user_agent |  | network_entity_match|
 +-----------------------+  +----------------+  +---------------------+
 | PK subnet_group       |  | PK id          |  | PK id               |
 |    first/last_seen_at |  | UQ ua_hash_256 |  | FK entity_id        |
 |    days_dormant       |  |    ua_hash_32  |  | FK range_id         |
 |    baseline_daily_avg |  |    auto_verdict|  +----------+----------+
 |    peak_daily_reqs    |  | manual_override|             | N
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
2. **`monitored_valves`:** Persisted runtime configurations for each discovered Valve (`monitor_mode`, `simulation_mode`, rate-limit thresholds, slot duration, `visitor_cookie_enabled`, `auth_tracking_enabled`, and `relevant_auth_scope`).
3. **`slot_snapshots`:** Completed and active time slots per server and valve instance with total request counts, active counters, hard-blocked counters (`blocked_counters`, HTTP 429), and soft-marked/simulated counters (`marked_counters`).
4. **`client_events`:** Granular rate-limit events distinguishing hard blocks (`status = 'BLOCKED'`), soft-marking/simulation threshold hits (`status = 'MARKED'`), and tracked active clients (`status = 'ACTIVE'`). Stores numeric IPv4/IPv6 boundaries (`ip_v4_start`, `ip_v4_end`) for sub-millisecond range lookups, visitor cookie and authentication counters (`returning_count`, `authenticated_count`), and first-trigger request samples (`sample_method`, `sample_uri`, `sample_user_agent`).
5. **`client_subnet_rollups`:** Persistent time-bucket aggregations per `/24` (IPv4) or `/64` (IPv6) subnet partition tracking `total_requests`, `active_requests`, `blocked_requests`, `marked_requests`, returning visitor / authenticated ratios, distinct client counts, and botnet heuristic metrics.
6. **`subnet_profiles`:** Long-term frequency baselines (30-day lookback with dynamic 3-phase calibration), dormancy periods, 24-hour surge multipliers, lifetime and 24h blocked vs. marked request totals (`total_blocked_requests`, `last_24h_blocked_requests`, `total_marked_requests`, `last_24h_marked_requests`), and 24h visitor cookie / authentication ratios per subnet partition for rapid detection of dormant breakouts and residential proxy sweeps.
7. **`daily_reports`:** Permanent daily operational summaries (`report_date`, `status`, `total_requests`, `total_blocked`, `total_marked`, `peak_requests_per_sec`, `peak_blocked_per_sec`, `peak_marked_per_sec`, and rendered GFM `markdown_content`) archived prior to raw telemetry retention cleanup.
8. **`network_annotations`:** Persistent operator knowledge archive, threat notes, and verdict badges (`LEGITIMATE`, `INTERNAL`, `SUSPICIOUS`, `MALICIOUS`, `INFO`) assigned to specific Subnets or ASNs.
9. **`dim_user_agent` & `user_agent_hourly_rollups`:** Persistent User-Agent identity catalog (`user_agent_hash` SHA-256 + `ua_hash_32` 32-bit FNV-1a), lifetime and 24h telemetry counters, Stage-0/3-pillar `auto_verdict`, non-overwritable `manual_override` / `operator_note` overrides, and slim hourly evaluation snapshots retained for up to 30 days.
10. **`network_entity` & `network_entity_match`:** Normalized directory of enriched client IPs and subnets with ASN, geolocation, threat classification, and cross-references to matched threat intelligence ranges.
11. **`intel_source` & `intel_range`:** Threat intelligence directory containing verified CIDR blocks from search engine bots, commercial AI scrapers, and Tor exit relays.
12. **`asn_info`:** Autonomous System catalog caching organization names and datacenter / hosting provider classifications.
13. **`crawler_feeds` & `bot_ip_ranges`:** Automatic synchronization catalog for official bot feeds (Googlebot, Bingbot, OpenAI, Anthropic) with versioning and orphan pruning.
14. **`poll_event_log`:** Diagnostic audit trail tracking background ingestion cycles (`blocked_events_ingested`, `marked_events_ingested`, `events_ingested`), wire data transfer volume (`payload_bytes`), server-side JSON rendering time (`server_generation_ms`), communication latency, warnings, and recovery gap-fills.
15. **`mitigation_rules`, `mitigation_ua_rules` & `mitigation_audit_log`:** Persistent dynamic CIDR block rules (`mitigation_rules`), TTL-bounded 32-bit FNV-1a User-Agent block rules (`mitigation_ua_rules`), and the unified audit trail (`mitigation_audit_log` with `target_type` distinguishing `CIDR` vs. `USER_AGENT`) tracking manual, autonomous, simulation, and fleet synchronization events.

---

## REST & Forensics API

| Endpoint | Method | Role / Mode Requirement | Description |
|---|---|---|---|
| `/api/v1/fleet` | `GET` | Read auth (`require-auth-for-read`) | Fleet overview: online status, 24h request totals, active valves. |
| `/api/v1/valves` | `GET` | Read auth (`require-auth-for-read`) | Query live and persisted Valve runtime configurations across the fleet or filtered by node. |
| `/api/v1/valves/{valveName}` | `GET` | Read auth (`require-auth-for-read`) | Query detailed runtime configuration for a specific named Valve on a specific server node. |
| `/api/v1/rollups/subnets` | `GET` | Read auth (`require-auth-for-read`) | Retrieve persistent subnet rollups with botnet heuristics. |
| `/api/v1/rollups/subnets/aggregate` | `POST` | `ADMIN` + `FULL` mode | On-demand trigger to calculate completed rollup buckets. |
| `/api/v1/rollups/subnets/profiles/refresh` | `POST` | `ADMIN` + `FULL` mode | Refresh behavioral 30-day subnet baselines. |
| `/api/v1/reputation/blocked-ips` | `GET` | Read auth (`require-auth-for-read`) | Export blocked IP addresses as a plain text blocklist for firewall ingest or JSON. |
| `/api/v1/poll-log` | `GET` | Read auth (`require-auth-for-read`) | Paginated query of polling audit log entries. |
| `/api/v1/notes` | `GET` / `POST` | Read auth / Write (`ADMIN`, `OPERATOR`, `AI_AGENT`) | List or create/update ASN and subnet investigative annotations. |
| `/api/v1/notes/{id}` | `GET` / `DELETE` | Read auth / Human write (`ADMIN`, `OPERATOR`) | Retrieve or delete an annotation (deletion forbidden for `AI_AGENT`). |
| `/api/v1/reports` | `GET` | Read auth (`require-auth-for-read`) | List persisted operational daily reports (`?limit=30`). |
| `/api/v1/reports/{date}` | `GET` | Read auth (`require-auth-for-read`) | Retrieve daily report Markdown and operator note for `YYYY-MM-DD`. |
| `/api/v1/reports/{date}/note` | `POST` / `DELETE` | Write / Human write | Add or delete daily report notes (`AI_AGENT` always appends cleanly). |
| `/api/v1/reports/generate` | `POST` | Write (`ADMIN`, `OPERATOR`, `AI_AGENT`) | Generate a report when raw telemetry is available (`409` if telemetry expired). |
| `/api/v1/mitigation/rules` | `GET` | Read auth (`require-auth-for-read`) | List currently active dynamic CIDR mitigation rules and mitigation-capable valves. |
| `/api/v1/mitigation/alerts` | `GET` | Read auth (`require-auth-for-read`) | Fetch autonomous mitigation alerts since `sinceId`. |
| `/api/v1/mitigation/preflight` | `POST` | Read auth / Authenticated caller | Dry-run preflight collateral-damage check for candidate CIDRs. |
| `/api/v1/mitigation/block` | `POST` | Write (`ADMIN`, `OPERATOR`, `AI_AGENT`) | Create or extend a dynamic CIDR block (strictly guarded for `AI_AGENT`). |
| `/api/v1/mitigation/asn-block` | `POST` | Write (`ADMIN`, `OPERATOR`, optionally `AI_AGENT`) | Block candidate subnets of an ASN (disabled for `AI_AGENT` unless allowed). |
| `/api/v1/mitigation/{id}/extend` | `POST` | Write (`ADMIN`, `OPERATOR`, `AI_AGENT` owner) | Extend rule TTL (`AI_AGENT` restricted to `AI_AGENT`-sourced rules and TTL cap). |
| `/api/v1/mitigation/{id}/revoke` | `POST` | Write (`ADMIN`, `OPERATOR`, `AI_AGENT` owner) | Revoke rule (`AI_AGENT` restricted to `AI_AGENT`-sourced rules). |

---

## Authentication, Multi-Token RBAC, Self-Protection & AI Guardrails

### 1. Multi-Token Role Model & Mode Intersection
Configure named tokens under `collector.security.tokens` using tokens generated by `generate-token`:
```yaml
collector:
  security:
    require-auth-for-read: true
    api-enabled: true
    session-ttl-seconds: 28800
    max-auth-failures: 5
    auth-lockout-seconds: 300
    tokens:
      - name: "soc-lead"
        role: ADMIN
        token: "<hex-token>"
        enabled: true
      - name: "soc-operator"
        role: OPERATOR
        token: "<hex-token>"
        enabled: true
      - name: "triage-bot"
        role: AI_AGENT
        token: "<hex-token>"
        enabled: true
      - name: "dashboard-tv"
        role: VIEWER
        token: "<hex-token>"
        enabled: true
```
The effective authorization is always the **intersection** of `collector.mode` and the authenticated token's role:
- **`ADMIN`** + **`FULL`** mode: full system, poller/enrichment/maintenance, operational, and UI access.
- **`OPERATOR`** (or `OPERATOR` mode): operational notes, daily reports, and manual/API mitigation (`preflight`, `block`, `extend`, `revoke`), without system-admin settings.
- **`AI_AGENT`**: permitted only through the guarded `/api/v1/{notes,reports,mitigation}/**` endpoints; Web-UI form mutations are rejected (`403`), audit entries are tagged `AI_AGENT:<token-name>`, and safety limits apply automatically.
- **`VIEWER`** (or `VIEWER` mode): strictly read-only; no token role can bypass `collector.mode: VIEWER`.

### 2. Fail-Closed API Defaults & Web-UI Session Cookie
- **Read API (`require-auth-for-read: true` by default):** Once any enabled token exists in `collector.security.tokens`, all `/api/v1/**` read and write endpoints require `Authorization: Bearer <token>`, `X-AntiDoS-Token: <token>`, `?token=<token>`, or a valid browser session cookie. If no tokens are configured yet, non-loopback non-demo API read requests fail closed (`401`).
- **Operational Write APIs (`/api/v1/{notes,reports,mitigation}/**`):** Strictly fail-closed even on `localhost` — `POST`/`DELETE` operational endpoints reject requests (`401`) unless at least one token is configured and the caller is authenticated.
- **Browser Session Login (`/login`, `/logout`):** Unauthenticated Web-UI requests redirect to `/login` (`HX-Redirect` for HTMX requests) when tokens are configured. Valid tokens issue an HMAC-SHA256 signed `HttpOnly` `SameSite=Lax` cookie (`_adc_session`) re-validated against currently configured active tokens on every request.

### 3. Collector Self-Protection (`AntiDoSValve` + Auth Lockout)
- **Embedded Valve (`collector.self-protection`):** Registers `AntiDoSValve` inside Collector's own embedded Tomcat container (default `enabled: true`, `allowed-requests-per-slot: 600` per 60s slot, `max-ip-cache-size: 10000`, static assets excluded). Floods are rejected early at Tomcat with HTTP `429`.
- **Auth Brute-Force Lockout:** Repeated invalid token or `/login` failures from the same IP (`request.getRemoteAddr()`) trigger an automatic temporary HTTP `429` lockout (`max-auth-failures: 5`, `auth-lockout-seconds: 300`).

### 4. AI-Agent Safety Guardrails (`collector.security.ai-guardrails`)
When authenticated as `AI_AGENT`:
- **Bounded Scope & TTL:** Enforces minimum CIDR specificity (`min-ipv4-prefix: 24`, `min-ipv6-prefix: 48`), caps block & extension durations (`max-ttl-minutes: 120`), and requires descriptive justification (`min-reason-length: 15`).
- **Collateral-Damage Refusal:** Any preflight critical warning (`hasCriticalWarnings()`) causes `422 COLLATERAL_DAMAGE_RISK` and cannot be bypassed via `forceOverride=true`.
- **Hourly Rate Limit & ASN Guard:** Enforces `max-blocks-per-hour: 20` across AI actions and blocks ASN batch blocking by default (`allow-asn-batch-block: false`).
- **Ownership & Human-Work Preservation:** `AI_AGENT` may extend or revoke only `AI_AGENT`-sourced mitigation rules (`403 OWNERSHIP_VIOLATION` on manual/auto rules), cannot delete annotations or daily report notes (`403 AI_DELETE_FORBIDDEN`), and cannot overwrite existing human-authored annotations without `append=true` (`409 HUMAN_NOTE_PROTECTED`).

