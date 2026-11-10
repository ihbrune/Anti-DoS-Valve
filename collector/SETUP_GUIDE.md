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
java -jar collector/target/anti-dos-collector-1.9.0.jar demo
# Or with a larger fleet (e.g. 3 instances per server type = 9 total servers A, B, C):
java -jar collector/target/anti-dos-collector-1.9.0.jar demo 3

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
Produces the executable Spring Boot JAR in `collector/target/anti-dos-collector-1.9.0.jar`.

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
java -jar collector/target/anti-dos-collector-1.9.0.jar test-endpoint \
  --url "http://localhost:8080/antidos-status" \
  --token "secretToken1" \
  --name "Web-Node-1"
```

### 4. Run the Collector
```bash
java -jar collector/target/anti-dos-collector-1.9.0.jar
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
sudo cp collector/target/anti-dos-collector-1.9.0.jar /opt/antidos-collector/anti-dos-collector.jar
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
 |   |  Step 3: Evaluate Sliding-Window Rate Limits (Local IP / Subnet)     |   |
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
| `auto-mitigation.carpet-window-hours` | `COLLECTOR_AUTO_MITIGATION_CARPET_WINDOW_HOURS` | `1` | Evaluation lookback window (in hours) across persistent subnet rollups for carpet attack detection. |
| `auto-mitigation.protected-asns` | `COLLECTOR_AUTO_MITIGATION_PROTECTED_ASNS` | `8075,16509,14618,15169,13335` | Comma-separated list of protected ASNs (e.g. Microsoft Azure, Amazon AWS, Google Cloud, Cloudflare) exempt from autonomous ASN-wide blocking. |
| `auto-mitigation.max-returning-ratio-pct` | `COLLECTOR_AUTO_MITIGATION_MAX_RETURNING_RATIO_PCT` | `5.0` | Maximum returning visitor cookie ratio (%) permitted for autonomous blocking. Protects legitimate residential ISP and mobile carrier CGNAT pools from collateral blocks. |
| `auto-mitigation.max-active-rules` | `COLLECTOR_AUTO_MITIGATION_MAX_ACTIVE_RULES` | `50` | Circuit breaker cap limiting the maximum number of concurrent autonomous dynamic rules across the fleet. |
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
2. **`monitored_valves`:** Persisted runtime configurations for each discovered Valve (`monitor_mode`, `simulation_mode`, rate-limit thresholds, slot duration, `visitor_cookie_enabled`, `auth_tracking_enabled`, and `relevant_auth_scope`).
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
15. **`mitigation_rules` & `mitigation_audit_log`:** Persistent dynamic CIDR block rules (`cidr`, `status`, `source`, `batch_id`, `expires_at`, `total_blocked_hits`, `peak_distinct_ips`, `deterrence_state`) and full operator/batch audit history (`CREATE`, `EXTEND`, `REVOKE`, `BATCH_CREATE`, `BATCH_REVOKE`).

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
