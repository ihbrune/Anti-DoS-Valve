# Anti-DoS Collector & Dashboard

The **Anti-DoS Collector** is a standalone management and analytics service designed to aggregate security events and metrics across a fleet of **Anti-DoS-Valve** instances running in multiple Tomcat servers.

---

## Features

* **Multi-Server & Multi-Valve Telemetry:** Periodically polls configured `/antidos-status` JSON endpoints across one or more servers.
* **Smart Slot Polling & Recovery:**
  * Automatically retrieves finalized previous slots (`slot=previous&blockedLimit=all&activeLimit=0&limit=all`).
  * Immutable completed slots are fetched only once upon completion, avoiding redundant polling cycles during long slot intervals.
  * Supports intermediate polling for long-window valves (e.g. 15-minute subnet aggregators) via in-progress slot upserts.
  * Recovers missed slots automatically using `slot=<slotKey>` if network connectivity was temporarily interrupted.
* **Flexible Storage (Zero-Ops to Enterprise Scale):**
  * **SQLite (Default):** Runs immediately out-of-the-box with zero configuration (`antidos-collector.db`).
  * **PostgreSQL:** Switchable via JDBC connection string in `application.yaml` or environment variables for high-volume enterprise deployments.
  * Versioned schema migrations managed automatically via **Flyway**.
* **Modern HTMX Dashboard & Specialized Forensics:**
  * Real-time fleet overview showing all connected servers and valves.
  * **Incident Explorer (`/events`):** Dedicated deep-dive view with multi-server and multi-valve selection, relative or exact custom date-time windows, CIDR range search matching both individual IPs and enclosing subnets, and rich ASN/Country/Bot classification badges (Datacenter, Residential, Search Engine, AI Bot, Mobile, Private Network).
  * **Top Offender Analytics (`/offenders`):** Aggregation ranking with **Subnet Rollup mode** (`/24` & `/64`) and **ASN Rollup mode** (`groupBy=ASN`) with automated **Rotating Proxy Cluster detection** to unmask distributed residential proxy botnets across rotating IPs.
  * **Verified Crawler & Bot Feed Manager (`/crawlers`):** Real-time status, automatic daily synchronization, and manual triggers for official search engine (Googlebot, Bingbot) and AI crawler (OpenAI GPTBot, Claude) IP ranges with automatic orphan pruning.
  * **Dark & Light Mode Support:** Fully responsive dark/light theme with instant header toggle, anti-FOUC (Flash of Unstyled Content) initialization, OS color scheme detection, and dual persistence via `localStorage` and cookies.
  * **Embedded Offline Documentation (`/help`):** The complete release guide, forensics manual, and configuration reference is bundled directly into the application JAR and accessible in the dashboard with live topic filtering and a sticky Table of Contents — 100% offline and air-gap ready without external network access or version drift.
  * Cross-navigation drill-down from Top Offenders directly into filtered incident logs.
* **Built-in Demo Mode (Out-of-the-Box Exploration):** Launch the collector with zero configuration against simulated multi-node Valve endpoints (Edge EU, API Gateway under active attack, Staging Node with telemetry diagnostics, and realistic ASN/Country profiles).
* **CLI Onboarding Tool:** Built-in command to test connectivity, verify tokens, and generate ready-to-use configuration blocks.

---

## Zero-Configuration Demo Mode

To explore the dashboard and telemetry engine without configuring or connecting any live Tomcat servers, launch the collector in **Demo Mode**:

```bash
# Using the Fat-JAR:
java -jar collector/target/anti-dos-collector-1.7.3.jar demo
# Or with a larger fleet (e.g. 3 instances per server type = 9 total servers A, B, C):
java -jar collector/target/anti-dos-collector-1.7.3.jar demo 3

# Or using Maven:
mvn spring-boot:run -pl collector -Dspring-boot.run.arguments="demo"
# Larger fleet with Maven:
mvn spring-boot:run -pl collector -Dspring-boot.run.arguments="demo 4"
# or:
mvn spring-boot:run -pl collector -Dspring-boot.run.profiles=demo
```

### What happens in Demo Mode?
* **Strict Database Isolation:** Uses a dedicated, separate SQLite database file (`antidos-collector-demo.db`). Any existing production databases (`antidos-collector.db` or PostgreSQL) are completely untouched and protected from test data pollution. To reset the demo, simply delete `antidos-collector-demo.db`.
* **Zero External Dependencies:** Runs 100% locally with embedded SQLite.
* **Simulated Multi-Server Fleet:**
  1. `Demo-Edge-EU`: Production web cluster with 3 valves (`Primary-Rate-Limiter` for single IP bursts, `Subnet-Guard` for IPv4 `/24` subnet aggregation, and `IPv6-Rate-Limiter` for dedicated IPv6 crawler mitigation).
  2. `Demo-API-Gateway`: Public API under active distributed DoS attack across mixed IPv4 and IPv6 botnet clusters, demonstrating real-time mitigation and Subnet Rollup forensics.
  3. `Demo-Staging-Node`: Host with simulated latency spikes and transient errors, demonstrating the Polling Event Audit Log and automatic recovery.
* **Instant 7-Day Telemetry Pre-Seeding:** On the very first launch, the demo database is pre-populated in less than 200 ms with 7 days of diurnal traffic curves, 3 distinct attack waves (yesterday's DDoS, credential stuffing, active ongoing attack), top offender IP rankings, and poll audit events (including warning & error recovery simulations).
* **100% Real Pipeline:** The scheduled poller, HTTP client, JSON deserialization, Flyway database persistence, and reactive HTMX dashboard all run exactly as in production.
* Open **`http://localhost:8090`** to view the live dashboard.

---

## Quickstart

### 1. Build the Collector
From the root directory of the project:
```bash
mvn package -pl collector
```
This produces the executable Spring Boot JAR in `collector/target/anti-dos-collector-1.7.3.jar`.

### 2. Configure Monitored Endpoints
Copy the provided example configuration file:
```bash
cp collector/src/main/resources/collector-config.example.yaml collector-config.yaml
```
Edit `collector-config.yaml` to specify your Tomcat server endpoints and status tokens:
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
You can test connectivity to any Valve endpoint before running the service:
```bash
java -jar collector/target/anti-dos-collector-1.7.3.jar test-endpoint \
  --url "http://localhost:8080/antidos-status" \
  --token "secretToken1" \
  --name "Web-Node-1"
```

### 4. Run the Collector
```bash
java -jar collector/target/anti-dos-collector-1.7.3.jar
```
Open your browser at **`http://localhost:8090`** to access the Fleet Dashboard.

---

## Production Setup & Zero-Friction Update Guide

To run the Collector as a robust, 24/7 background service in production—and ensure that future updates via `git pull` from GitHub will **never** overwrite your configuration, delete your database, or cause git merge conflicts—follow this recommended deployment architecture.

### Decoupling Architecture: Code vs. Configuration vs. Data

In a production environment, keep the three domains strictly separated:

| Component | Recommended Location | Purpose |
|---|---|---|
| **Source & Git Repo** | `/opt/anti-dos-valve` or `~/build/Anti-DoS-Valve` | Repository where `git pull` and `mvn package` are executed. Contains **no** runtime credentials or databases. |
| **Service Binary** | `/opt/antidos-collector/anti-dos-collector.jar` | Production Fat-JAR executed by systemd. |
| **Configuration** | `/etc/antidos/collector-config.yaml` | System configuration with server URLs, tokens, and thresholds. **Outside Git**, automatically imported on startup. |
| **Persistent Data** | `/var/lib/antidos/` | SQLite database (`antidos-collector.db`), GeoIP MMDB files, and custom ASN overlays. |

---

### Step-by-Step Production Deployment (Linux & systemd)

#### Step 1: Create Dedicated System User & Directories
Create an unprivileged system user and the standard production directories:
```bash
# Create dedicated system user and group (-U)
sudo useradd -r -U -s /bin/false -d /var/lib/antidos -c "Anti-DoS Collector Service" antidos || true

# Create configuration, data, and binary directories
sudo mkdir -p /etc/antidos /var/lib/antidos /opt/antidos-collector
sudo chown -R antidos:antidos /var/lib/antidos /etc/antidos /opt/antidos-collector
```

#### Step 2: Initialize Configuration (`/etc/antidos/collector-config.yaml`)
Copy the template configuration into `/etc/antidos/`:
```bash
sudo cp collector/src/main/resources/collector-config.example.yaml /etc/antidos/collector-config.yaml
sudo chown antidos:antidos /etc/antidos/collector-config.yaml
sudo chmod 600 /etc/antidos/collector-config.yaml
```

Edit `/etc/antidos/collector-config.yaml` to configure your persistent database path, fleet endpoints, and security tokens:
```yaml
spring:
  datasource:
    # Dedicated persistent SQLite database path
    url: "jdbc:sqlite:/var/lib/antidos/antidos-collector.db?busy_timeout=10000"

collector:
  poll-interval-seconds: 15
  retention-days: 30
  poll-log-retention-days: 1
  slow-poll-threshold-ms: 1000
  parallel-fleet-polling: true

  # ---------------------------------------------------------------------------
  # Telemetry & Active Tracking Rules (3-Tier Cascade)
  # ---------------------------------------------------------------------------
  # 1. Global Default: applied to all valves across all servers unless overridden
  default-valve-rules:
    collect-active: false         # Default: activeLimit=0 (saves Valve CPU & network bandwidth)
    active-min-count: 10          # Default threshold when active collection is enabled
    active-limit: 1000            # Safety limit cap per slot

  # 2. Global Valve-Name Rules: applies across all servers in your fleet by valve name
  valve-rules:
    "Subnet-24-Limiter":          # Subnet aggregator: capture every subnet immediately
      collect-active: true
      active-min-count: 1
    "IP-Aggregator":              # Standard IP limiter: noise filter, capture from count 15
      collect-active: true
      active-min-count: 15
    "Api-Overlapping-Limiter":    # Overlapping URL valve: disable active telemetry (prevents double counting)
      collect-active: false

  # Monitored Tomcat server endpoints
  endpoints:
    - name: "Prod-Web-01"
      url: "https://web01.internal.example.com/antidos-status"
      token: "yourSecureStatusToken1"
      poll-intermediate-slots: false
      enabled: true
      valves:
        - "IP-Aggregator"
        - "Subnet-24-Limiter"

    - name: "Prod-Web-02"
      url: "https://web02.internal.example.com/antidos-status"
      token: "yourSecureStatusToken2"
      poll-intermediate-slots: false
      enabled: true

    - name: "Staging-Node"
      url: "https://staging.internal.example.com/antidos-status"
      token: "stagingToken"
      valves:
        - name: "IP-Aggregator"
          active-min-count: 3     # Endpoint override: lower threshold for staging analysis

  enrichment:
    enabled: true
    asn-database-path: "/var/lib/antidos/dbip-asn-lite.mmdb"
    country-database-path: "/var/lib/antidos/dbip-country-lite.mmdb"
    custom-datacenter-asns-file: "/etc/antidos/custom-datacenter-asns.txt"
```

> **Note on Auto-Discovery:** The Collector automatically looks for `/etc/antidos/collector-config.yaml` and `${user.home}/.antidos/collector-config.yaml` upon startup. No extra `--spring.config.additional-location` flag is required.

#### Step 3: Test Endpoint Connectivity via CLI
Before starting the background service, verify network connectivity and token authentication against your live Tomcat nodes:
```bash
java -jar collector/target/anti-dos-collector-1.7.3.jar test-endpoint \
  --url "https://web01.internal.example.com/antidos-status" \
  --token "yourSecureStatusToken1" \
  --name "Prod-Web-01"
```

#### Step 4: Deploy the Fat-JAR & Install systemd Service
Deploy the packaged Fat-JAR:
```bash
sudo cp collector/target/anti-dos-collector-1.7.3.jar /opt/antidos-collector/anti-dos-collector.jar
sudo chown antidos:antidos /opt/antidos-collector/anti-dos-collector.jar
```

Create the systemd unit file `/etc/systemd/system/antidos-collector.service`:
```ini
[Unit]
Description=Anti-DoS Fleet Collector & Analytics Service
After=network.target

[Service]
Type=simple
User=antidos
Group=antidos
WorkingDirectory=/var/lib/antidos
ExecStart=/usr/bin/java -jar /opt/antidos-collector/anti-dos-collector.jar
Restart=always
RestartSec=10
SuccessExitStatus=143

# Security Sandboxing
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/antidos
ReadOnlyPaths=/etc/antidos

[Install]
WantedBy=multi-user.target
```

Reload systemd, enable the service on boot, and start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now antidos-collector
sudo systemctl status antidos-collector
```

Access the dashboard at **`http://<server-ip>:8090`**.

---

### Frictionless GitHub Updates (`git pull` Workflow)

Whenever a new version, performance improvement, or bug fix is published on GitHub, you can upgrade your production system in seconds without touching your configuration or backing up database files:

```bash
# 1. Pull latest source code from GitHub
cd /opt/anti-dos-valve
git pull

# 2. Build the updated executable JAR
mvn package -pl collector -DskipTests

# 3. Replace the active binary
sudo cp collector/target/anti-dos-collector-*.jar /opt/antidos-collector/anti-dos-collector.jar
sudo chown antidos:antidos /opt/antidos-collector/anti-dos-collector.jar

# 4. Restart the collector service
sudo systemctl restart antidos-collector
```

#### Why is this update workflow 100% safe?
1. **Zero Git Merge Conflicts:** Because `/etc/antidos/collector-config.yaml` and `/var/lib/antidos/antidos-collector.db` live outside the repository, your git working tree stays completely pristine. `git pull` will always succeed cleanly.
2. **Configuration Protection:** Your server endpoints, credentials, and custom thresholds are never modified or reset during repository updates.
3. **Automated Database Schema Migrations:** All database changes across versions are managed via **Flyway**. When the newly built JAR boots up, it automatically checks the database schema and applies any pending migrations safely in a single transaction.
4. **Log Inspection:** Monitor the service startup after an update at any time with:
   ```bash
   journalctl -u antidos-collector -f
   ```

---

### Alternative: User-Home Standalone Setup (`~/.antidos/`)

For smaller server environments or environments where you do not have root/systemd privileges, you can achieve the exact same decoupling in your user account:

1. Create directory `~/.antidos/`
2. Place your configuration in `~/.antidos/collector-config.yaml`
3. Point your database URL to `jdbc:sqlite:${user.home}/.antidos/antidos-collector.db?busy_timeout=10000`
4. The collector will automatically detect `~/.antidos/collector-config.yaml` on startup.
5. In the git repository, `git pull` and `mvn package` can be run anytime without touching `~/.antidos/`.

---

## Database Configuration

### SQLite (Default)
By default, the collector stores data in a local SQLite database named `antidos-collector.db` in the current working directory.

To ensure the database is always stored in a fixed location regardless of the working directory from which you launch the collector, specify a fixed or home-relative path:

**Via `collector-config.yaml`:**
```yaml
spring:
  datasource:
    url: "jdbc:sqlite:${user.home}/.antidos/antidos-collector.db"
    # or an absolute path:
    # url: "jdbc:sqlite:/var/lib/antidos/antidos-collector.db"
```

**Via Environment Variable:**
```bash
export SPRING_DATASOURCE_URL="jdbc:sqlite:${HOME}/.antidos/antidos-collector.db"
```

*Note:* The Collector automatically creates any missing parent directories (e.g. `~/.antidos/`) upon startup.

### PostgreSQL (Production Fleet)
To connect to a PostgreSQL database, provide standard Spring Data Source environment variables or edit `collector-config.yaml`:
```bash
export SPRING_DATASOURCE_URL="jdbc:postgresql://localhost:5432/antidos_collector"
export SPRING_DATASOURCE_USERNAME="postgres"
export SPRING_DATASOURCE_PASSWORD="password"
java -jar collector/target/anti-dos-collector-1.7.3.jar
```
Flyway will automatically initialize the PostgreSQL schema upon startup.

---

## Polling Event Log & Audit Diagnostics

The collector records every polling cycle against each monitored endpoint in a dedicated audit log table (`poll_event_log`):
* **Status tracking:** Distinguishes between `SUCCESS`, `WARNING` (e.g. slow response or partial valve errors), and `ERROR` (connection refused, timeout, 401/404).
* **Latency Monitoring:** Automatically flags polling cycles that take longer than `slow-poll-threshold-ms` (default: 1000 ms).
* **Configurable Retention:** Keeps the database lean by purging log entries older than `poll-log-retention-days` (default: 1 day).
* **Dedicated UI with Infinite Scrolling:** Available under `/poll-log` with quick status filtering (All / Errors Only / Warnings & Errors) and server selection.

### Configuration Reference

```yaml
collector:
  poll-interval-seconds: 15     # Interval between collector poll runs (default: 15s)
  parallel-fleet-polling: true  # Concurrently poll different servers via Virtual Threads (valves on same server remain sequential)
  retention-days: 30            # Retention for slot telemetry and client incident events (default: 30 days)
  poll-log-retention-days: 1    # Retention for polling event audit log entries (default: 1 day)
  entity-retention-days: 60     # Retention for inactive unreferenced network entities (default: 60 days)
  slow-poll-threshold-ms: 1000  # Latency threshold before marking poll status as WARNING (default: 1000 ms)
```

---

## Data Retention & Entity Hygiene Strategy

To prevent unbounded database growth and remain compliant with IP data retention guidelines (e.g. MaxMind GeoLite2 EULA and GDPR data minimization), the Collector runs an automated daily cleanup job at **03:00 AM**:

1. **Telemetry & Incident Retention (`retention-days`, default: 30 days; `retention-days-active`, default: 7 days):**
   * High-resolution slot snapshots (`slot_snapshots`) and raw client events (`client_events`) older than `retention-days` (for blocked events) or `retention-days-active` (for active events) are permanently purged.
2. **Audit Diagnostics Retention (`poll-log-retention-days`, default: 1 day):**
   * Endpoint health checks, latency records, and polling logs (`poll_event_log`) are pruned after 24 hours to keep the diagnostic audit lean.
3. **Orphan Entity Cleanup (`entity-retention-days`, default: 60 days):**
   * Client IP addresses and subnets are stored in a normalized `network_entity` table. When historic events age out and are deleted, older entities may no longer be referenced anywhere.
   * Entities that have not been seen for more than `entity-retention-days` **and** have zero associated event records in `client_events` are automatically deleted along with their feed matches (`network_entity_match`). Active entities with existing events are always preserved.

## IP Enrichment: ASN, Geo-Location & Verified Bots

The collector enriches blocked client IPs with Autonomous System Numbers (ASN), Organizations, Country codes, and classified client categories (`DATACENTER`, `RESIDENTIAL`, `SEARCH_ENGINE`, `AI_CRAWLER`, `MOBILE`, `PRIVATE_NETWORK`).

### 1. Acquiring Offline MMDB Databases

The collector directly queries binary `.mmdb` files using memory-mapped Bit-Trees ($O(\log n)$ lookup speed, zero relational database overhead). Two popular free data sources:

* **DB-IP Lite (Free, CC BY 4.0, No Registration Required):**
  * **ASN Database:** [dbip-asn-lite.mmdb.gz](https://db-ip.com/db/download/ip-to-asn-lite)
  * **Country Database:** [dbip-country-lite.mmdb.gz](https://db-ip.com/db/download/ip-to-country-lite)
  * Download and extract: `gunzip dbip-asn-lite.mmdb.gz dbip-country-lite.mmdb.gz`
* **MaxMind GeoLite2 (Free, Registration Required):**
  * GeoLite2-ASN and GeoLite2-Country
  * Automatically kept up-to-date via the official `geoipupdate` tool (typically stored in `/usr/share/GeoIP/`).

### 2. Configuration

Add the database paths to your `collector-config.yaml` or set environment variables:

```yaml
collector:
  enrichment:
    enabled: true
    ttl-days: 30                                               # metadata freshness TTL in days (MaxMind GeoLite2 compliance)
    asn-database-path: "/var/data/dbip-asn-lite.mmdb"           # or /usr/share/GeoIP/GeoLite2-ASN.mmdb
    country-database-path: "/var/data/dbip-country-lite.mmdb"   # or /usr/share/GeoIP/GeoLite2-Country.mmdb
    custom-datacenter-asns-file: "custom-datacenter-asns.txt"  # optional custom Datacenter ASN overlay
    crawler-sync-enabled: true                                 # automated search engine & AI bot feed sync
    crawler-sync-cron: "0 0 4 * * *"                           # daily at 04:00 AM
```

Or via environment variables:
```bash
export COLLECTOR_ENRICHMENT_ASN_DATABASE_PATH="/var/data/dbip-asn-lite.mmdb"
export COLLECTOR_ENRICHMENT_COUNTRY_DATABASE_PATH="/var/data/dbip-country-lite.mmdb"
export COLLECTOR_ENRICHMENT_CUSTOM_DATACENTER_ASNS_FILE="/etc/antidos/custom-datacenter-asns.txt"
```

> **Backwards Compatibility:** Legacy property names `custom-hosting-asns-file` and `custom-hosting-asns` remain fully supported as aliases.

### 3. How Enrichment Operates

#### A. MMDB Database vs. Classification Rules
* **Offline MMDB Database (DB-IP Lite or MaxMind GeoLite2):** Queries memory-mapped `.mmdb` files to extract raw facts: client ASN number (e.g., `32934`), organisation string (e.g., `"FACEBOOK"`), and country code. The database itself does not classify client intent.
* **Collector Classification Engine:** Evaluates the resolved ASN, organisation name, and threat intelligence to assign a concrete category (`DATACENTER`, `SEARCH_ENGINE`, `AI_CRAWLER`, `TOR_EXIT_NODE`, `MOBILE`, `RESIDENTIAL`, or `UNKNOWN`).

#### B. Layered Datacenter ASN Hierarchy
The set of ASNs classified as `DATACENTER` (Cloud, VPS, Colocation, and Hyperscaler infrastructure) is resolved in three hierarchical tiers:
1. **Built-in Defaults (`classpath:asns/default-datacenter-asns.txt`):** Baseline list covering major cloud providers and hyperscalers (AWS, Azure, GCP, Meta/Facebook, Oracle, Alibaba, Hetzner, OVH, DigitalOcean, Cloudflare, Fastly, etc.).
2. **File Overlay (`custom-datacenter-asns.txt`):** Takes precedence over defaults and allows operators to customize classification without Git conflicts:
   * `+12345` (forces ASN 12345 to be classified as Datacenter)
   * `-24940` (whitelists / removes ASN 24940 from Datacenter classification)
3. **YAML Configuration (`collector-config.yaml`):** Additional ASNs can be configured under `collector.enrichment.custom-datacenter-asns: [ 77777, ... ]`.

#### C. Classification Priority & Precedence
When an incident IP is enriched by `EntityResolver`, the following strict priority pipeline is applied:

| Priority | Step / Data Source | ClientType Result | Description |
|---|---|---|---|
| **1. Highest** | **Private Network & Loopback** | `PRIVATE_NETWORK` | RFC 1918 (10.x, 192.168.x, 172.16-31.x), RFC 4193 ULA, loopback (127.0.0.1, `::1`). Terminates evaluation immediately. |
| **2.** | **Dynamic Intel Feeds (`IntelRegistry`)** | `SEARCH_ENGINE`, `AI_CRAWLER`, `TOR_EXIT_NODE` | Verified Googlebot, Bingbot, Applebot, OpenAI, Tor exit nodes. Always overrides ASN categorization. |
| **3.** | **MMDB Lookup** | *(Raw Metadata)* | Retrieves numerical `asn`, `asOrg`, and `countryCode` from offline `.mmdb` files. |
| **4.** | **Datacenter ASN Match** | `DATACENTER` | Checked against the combined `hostingAsns` set (default + custom overlay + YAML). |
| **5.** | **Heuristic: Hosting Keywords** | `DATACENTER` | Triggered if `asOrg` contains `cloud`, `vps`, `hosting`, `datacenter`, `server`, `cdn`, `colocation`, etc. |
| **6.** | **Heuristic: Mobile Keywords** | `MOBILE` | Triggered if `asOrg` contains `cellular`, `mobile`, `5g`, `4g`, `wireless`, `cgnat`, etc. |
| **7.** | **Heuristic: Residential Keywords** | `RESIDENTIAL` | Triggered if `asOrg` contains consumer ISP markers: `telekom`, `vodafone`, `dsl`, `cable`, `fiber`, `broadband`, `residential`, `consumer`, `isp`, `comcast`, `spectrum`, `o2`, `telefonica`, etc. |
| **8. Fallback** | **Unclassified / Unknown** | `UNKNOWN` | If no rules or keywords match, the entity remains neutral (`UNKNOWN` / *Unclassified*), avoiding false residential classifications for enterprise, corporate, or university networks. |

#### D. Performance & Lifecycle Management
* **Zero-Ops Fallback:** If no MMDB database paths are configured, the collector boots immediately without errors. Verified bot detection and private network classification remain operational out-of-the-box.
* **Asynchronous Virtual Thread Processing:** Pollers write incidents with status `PENDING` without blocking or polling latency. `BackgroundEnrichmentWorker` resolves ASNs, Geolocation, and Client Types asynchronously in small batches on Java 21 Virtual Threads.
* **Multi-Source Intelligence & Entity Normalization:** Client IP addresses and subnets are deduplicated and maintained in a normalized `network_entity` registry. Incidents reference this entity via `entity_id`, avoiding redundant Geo/ASN queries and unnecessary database row churn. An in-memory interval index (`IntelRegistry`) matches IPs against intelligence feeds with sub-microsecond latency.
* **Metadata Freshness & MaxMind Compliance (`ttl-days`):** In compliance with MaxMind GeoLite2 guidelines, enrichment data has a configurable expiration (`ttl-days`, default: 30 days). Entities resolved older than `ttl-days` ago are automatically scheduled for background re-enrichment. Local intranet networks (`PRIVATE_NETWORK`) remain permanently valid.
* **Crawler & Anonymizer Feed Sync & Management UI (`/crawlers`):** Automated periodic sync fetches official IP ranges for Googlebot, Bingbot, Applebot, OpenAI GPTBot, ChatGPT-User, and Tor Bulk Exit Nodes (`torbulkexitlist`). Extensible via `collector-config.yaml` (`crawler-feeds:<key>`). Manual syncs can be triggered per feed or globally via the `/crawlers` dashboard. Removed feed configurations automatically purge orphaned IP ranges from the database.

### 4. Automated Daily Updates via Cron Job or Systemd Timer

To keep ASN mappings and Country geolocation accurate without manual administrator intervention, automate the download every 24 hours.

#### Option A: DB-IP Lite (Free, CC BY 4.0, No Registration Required)

The repository provides a production-ready update script in [`collector/scripts/update-antidos-mmdb.sh`](file:///Users/hbrune/Antigravity/Anti-DoS-Valve/collector/scripts/update-antidos-mmdb.sh). It downloads the latest monthly ASN and Country databases, verifies integrity, replaces the files atomically in `/var/lib/antidos/`, applies file ownership, and restarts the service if active.

1. **Install the script:**
   ```bash
   sudo cp collector/scripts/update-antidos-mmdb.sh /usr/local/bin/update-antidos-mmdb.sh
   sudo chmod +x /usr/local/bin/update-antidos-mmdb.sh
   ```

2. **Test manual execution:**
   ```bash
   sudo /usr/local/bin/update-antidos-mmdb.sh /var/lib/antidos antidos antidos
   ```

3. **Schedule daily execution via Cron (`/etc/cron.d/antidos-mmdb-update`):**
   ```cron
   # /etc/cron.d/antidos-mmdb-update
   # Update DB-IP Lite databases every night at 03:30 AM
   30 3 * * * root /usr/local/bin/update-antidos-mmdb.sh /var/lib/antidos antidos antidos >> /var/log/antidos-mmdb-update.log 2>&1
   ```
   *(Alternatively, place the script or a symlink into `/etc/cron.daily/`)*

#### Option B: MaxMind GeoLite2 via `geoipupdate`

If using MaxMind GeoLite2, use the official `geoipupdate` tool:

1. **Install `geoipupdate`:**
   ```bash
   sudo apt install geoipupdate   # Debian/Ubuntu
   # or: sudo dnf install geoipupdate # Fedora/RHEL
   ```

2. **Configure `/etc/GeoIP.conf`:**
   ```ini
   AccountID <Your-Account-ID>
   LicenseKey <Your-License-Key>
   EditionIDs GeoLite2-ASN GeoLite2-Country
   ```

3. **Schedule daily update via Cron (`/etc/cron.d/geoipupdate`):**
   ```cron
   # /etc/cron.d/geoipupdate
   # Update MaxMind databases every night at 03:30 AM and reload collector
   30 3 * * * root /usr/bin/geoipupdate && (systemctl is-active --quiet antidos-collector && systemctl restart antidos-collector || true)
   ```
   *(Or enable the systemd timer: `sudo systemctl enable --now geoipupdate.timer`)*

---

## Relational Database Schema & Data Model

The Anti-DoS Collector employs a relational database model supported identically across **SQLite** (default zero-ops embedded database) and **PostgreSQL** (production multi-server scale). All schema definitions and iterative version updates are governed by **Flyway migrations** (`src/main/resources/db/migration/{sqlite,postgresql}`).

The model separates high-volume, transient telemetry data (slots, incident events) from a normalized client entity registry (`network_entity`) and multi-source threat intelligence feeds (`intel_source`, `intel_range`).

```
 +------------------------+             +------------------------+
 |  endpoint_heartbeats   |             |     poll_event_log     |
 +------------------------+             +------------------------+
 | PK server_id           |<- - - - - - | id (PK)                |
 |    url                 |  (logical)  | server_id              |
 |    is_online           |             | status, poll_time      |
 |    last_poll_at        |             | http_status_code, ...  |
 +-----------+------------+             +------------------------+
             | 1
             | (logical)
             | N
 +-----------v------------+
 |     slot_snapshots     |
 +------------------------+
 | PK id                  |
 | UQ (server, valve, key)|
 |    total_requests      |
 |    active_counters     |
 |    blocked_counters    |
 |    is_completed, ...   |
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
 |    subnet_group, client_type, country_code, asn, as_org       |
 | FK entity_id -------------------------------------------+     |
 +---------------------------------------------------------|-----+
                                                           |
                                                           | N
                                                           | 1
 +---------------------+             +---------------------v-----+
 |      asn_info       |             |      network_entity       |
 +---------------------+             +---------------------------+
 | PK asn              |<- - - - - - | PK id                     |
 |    as_org           |  (logical)  | UQ client_key             |
 |    category         |             |    ip_v4_start / ip_v4_end|
 |    category_source  |             |    client_type, tags      |
 |    updated_at       |             |    enrichment_status      |
 +---------------------+             |    resolved_at, first/last|
                                     +-------------+-------------+
                                                   | 1
                                                   | N
                                     +-------------v-------------+
                                     |   network_entity_match    |
                                     +---------------------------+
                                     | PK,FK entity_id           |
                                     | PK,FK range_id            |
                                     |       matched_at          |
                                     +-------------+-------------+
                                                   | N
                                                   | 1
 +---------------------+             +-------------v-------------+
 |    intel_source     | 1         N |        intel_range        |
 +---------------------+-------------+---------------------------+
 | PK source_key       |             | PK id                     |
 |    source_type      |             | FK source_key             |
 |    name, category   |             |    cidr, prefix           |
 |    url, version     |             |    ip_v4_start / ip_v4_end|
 |    status, ...      |             |    category, label, ...   |
 +---------------------+             +---------------------------+
```

---

### Entity Relationships Overview

1. **`endpoint_heartbeats` &rarr; `slot_snapshots` & `poll_event_log` (1:N, Logical):**
   * `endpoint_heartbeats` tracks the operational availability of each monitored Tomcat instance identified by `server_id`.
   * `slot_snapshots` stores historical time-slot windows captured from the valve instances running on that server.
   * `poll_event_log` records granular telemetry collection events, round-trip latencies, and error diagnostics for that server.
2. **`slot_snapshots` &rarr; `client_events` (1:N, Logical):**
   * Each time-slot snapshot contains zero or more client traffic records (blocked incidents or top active monitored clients), matched by the composite key `(server_id, valve_name, slot_key)`.
3. **`network_entity` &rarr; `client_events` (1:N, Foreign Key):**
   * Normalization layer: Instead of redundantly evaluating ASN, country, and bot signatures for identical IP addresses or subnets across thousands of time-slots, `client_events.entity_id` references the shared `network_entity` master record.
   * For backwards compatibility and high-throughput bulk insertions, denormalized network and classification fields are also kept directly on `client_events`.
4. **`intel_source` &rarr; `intel_range` (1:N, Foreign Key with CASCADE):**
   * An intelligence provider (e.g. Googlebot feed, OpenAI bot list, Tor exit list) publishes one or more CIDR IP ranges. Deleting or updating a source cascades to its constituent ranges.
5. **`network_entity` &harr; `intel_range` via `network_entity_match` (N:M, Foreign Keys):**
   * Join table storing provenance. When an entity is recognized as a verified search engine or AI crawler, `network_entity_match` records the exact rule(s) and CIDR range(s) that triggered the classification.
6. **`asn_info` &rarr; `network_entity` (1:N, Logical):**
   * Reference catalog of Autonomous System Numbers, their associated corporate or ISP entities, and their categorized classification (`DATACENTER`, `RESIDENTIAL`, etc.).

---

### Table Catalog & Attribute Reference

#### 1. `endpoint_heartbeats`
Stores the real-time operational status, round-trip latency, and health of each configured Tomcat endpoint.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `server_id` | `VARCHAR(100)` | **PRIMARY KEY** | Unique logical server/host identifier (e.g. `Web-Node-1`, `Demo-Edge-EU`). |
| `url` | `VARCHAR(255)` | `NOT NULL` | Monitored `/antidos-status` HTTP(S) endpoint URL. |
| `is_online` | `BOOLEAN` | `NOT NULL DEFAULT 0` | Flag indicating whether the endpoint responded with HTTP 200 on the last poll. |
| `last_poll_at` | `TIMESTAMP` | *Nullable* | Exact timestamp of the most recent polling attempt. |
| `last_success_at` | `TIMESTAMP` | *Nullable* | Exact timestamp of the most recent successful response. |
| `last_error` | `TEXT` | *Nullable* | Error message, HTTP failure code, or connection timeout diagnostics. |
| `response_time_ms`| `INTEGER` | `DEFAULT 0` | Round-trip request/response latency in milliseconds. |
| `valves_count` | `INTEGER` | `DEFAULT 0` | Number of distinct Anti-DoS Valve instances reported by this server. |

---

#### 2. `slot_snapshots`
Records aggregated traffic statistics and counter tallies for each monitoring time-slot across all valve instances. Powers timeline charts and fleet overview metrics.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `INTEGER` / `BIGSERIAL` | **PRIMARY KEY**, Auto-inc | Unique surrogate identifier for the slot snapshot. |
| `server_id` | `VARCHAR(100)` | `NOT NULL` | Server identifier matching `endpoint_heartbeats.server_id`. |
| `valve_name` | `VARCHAR(100)` | `NOT NULL` | Configured `monitorName` of the valve (e.g. `AntiDoS-IP`, `Subnet-Guard`). |
| `slot_key` | `BIGINT` | `NOT NULL` | Epoch-based slot identifier representing the discrete time-window. |
| `start_time` | `TIMESTAMP` | `NOT NULL` | Exact start time of the time-slot window. |
| `end_time` | `TIMESTAMP` | `NOT NULL` | Exact end time of the time-slot window. |
| `total_requests` | `BIGINT` | `NOT NULL DEFAULT 0` | Total HTTP requests handled by the valve during this slot. |
| `active_counters` | `INTEGER` | `NOT NULL DEFAULT 0` | Number of distinct client IPs or subnets actively tracked in this slot. |
| `blocked_counters`| `INTEGER` | `NOT NULL DEFAULT 0` | Number of client IPs or subnets that exceeded limits and were blocked. |
| `is_completed` | `BOOLEAN` | `NOT NULL DEFAULT 0` | `1` (true) if the slot interval has passed and is immutable; `0` if in-progress. |
| `last_polled_at` | `TIMESTAMP` | `NOT NULL` | Timestamp when this snapshot was fetched and written to storage. |

* **Unique Constraint:** `uq_slot_snapshot` on `(server_id, valve_name, slot_key)`.
* **Indexes:** `idx_slot_server_valve (server_id, valve_name)`, `idx_slot_start_time (start_time)`, `idx_slot_completed (is_completed)`.

---

#### 3. `client_events`
Stores individual client traffic records (both rate-limiting incidents for blocked clients and top active monitored clients). Powers the **Incident & Traffic Explorer (`/events`)** and **Top Offender Analytics (`/offenders`)**.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `INTEGER` / `BIGSERIAL` | **PRIMARY KEY**, Auto-inc | Unique surrogate identifier for the event. |
| `server_id` | `VARCHAR(100)` | `NOT NULL` | Originating Tomcat server. |
| `valve_name` | `VARCHAR(100)` | `NOT NULL` | Originating Anti-DoS Valve instance. |
| `slot_key` | `BIGINT` | `NOT NULL` | Associated time-slot identifier. |
| `slot_time` | `TIMESTAMP` | `NOT NULL` | Timestamp of the associated time-slot. |
| `client_key` | `VARCHAR(64)` | `NOT NULL` | Target IP address (e.g. `198.51.100.42`, `2001:db8::1`) or subnet (`198.51.100.0/24`). |
| `request_count` | `INTEGER` | `NOT NULL DEFAULT 0` | HTTP requests made by this client in the slot prior to or during blocking/monitoring. |
| `retained_count`| `INTEGER` | `NOT NULL DEFAULT 0` | Historical request weight carried over from previous slots. |
| `is_locked` | `BOOLEAN` | `NOT NULL DEFAULT 1` | Indicates whether the client was actively locked/blocked (HTTP 429). |
| `status` | `VARCHAR(16)` | `NOT NULL DEFAULT 'BLOCKED'` | Lifecycle status: `'BLOCKED'` (HTTP 429 rate limit applied) or `'ACTIVE'` (monitored active traffic). |
| `is_completed` | `BOOLEAN` | `NOT NULL DEFAULT 0` | `1` if the slot has finalized; `0` if updated during an active slot. |
| `last_updated_at`| `TIMESTAMP` | `NOT NULL` | Timestamp of the latest counter update. |
| `ip_version` | `SMALLINT` | `NOT NULL DEFAULT 4` | Protocol family: `4` (IPv4) or `6` (IPv6). |
| `cidr_prefix` | `SMALLINT` | `NOT NULL DEFAULT 32` | Subnet mask length (e.g. 32 for single IPv4, 24 for `/24`, 128/64 for IPv6). |
| `ip_v4_start` | `BIGINT` | *Nullable* | Numerical starting boundary of the IPv4 range (unsigned 32-bit as signed 64-bit integer). |
| `ip_v4_end` | `BIGINT` | *Nullable* | Numerical ending boundary of the IPv4 range. |
| `ip_v6_start` | `VARCHAR(16)` | *Nullable* | 16-byte binary string representing the start of the 128-bit IPv6 address range. |
| `ip_v6_end` | `VARCHAR(16)` | *Nullable* | 16-byte binary string representing the end of the 128-bit IPv6 address range. |
| `subnet_group` | `VARCHAR(64)` | *Nullable* | Canonical enclosing network block (e.g. IPv4 `/24` or IPv6 `/64`) for Subnet Rollup grouping. |
| `asn` | `BIGINT` | *Nullable* | Autonomous System Number resolved via MMDB. |
| `as_org` | `VARCHAR(255)` | *Nullable* | Registered organization name of the AS (e.g. `CLOUDFLARENET`, `AMAZON-02`). |
| `country_code` | `VARCHAR(2)` | *Nullable* | ISO 3166-1 alpha-2 two-letter country code. |
| `client_type` | `VARCHAR(32)` | `NOT NULL DEFAULT 'UNKNOWN'` | Client classification (`DATACENTER`, `RESIDENTIAL`, `SEARCH_ENGINE`, `AI_CRAWLER`, etc.). |
| `enrichment_status`| `VARCHAR(16)` | `NOT NULL DEFAULT 'PENDING'` | Lifecycle status: `PENDING`, `RESOLVED`, or `FAILED`. |
| `entity_id` | `BIGINT` | **FOREIGN KEY** (Nullable) | References `network_entity(id)` master record. |

* **Unique Constraint:** `uq_client_event` on `(server_id, valve_name, slot_key, client_key)`.
* **Range & Rollup Indexes:** `idx_events_v4_range`, `idx_events_v6_range`, `idx_events_subnet_group`, `idx_events_asn`, `idx_events_client_type`, `idx_events_country`, `idx_events_status_time (status, slot_time)`, `idx_events_filter (slot_time, server_id, valve_name)`.

---

#### 4. `network_entity`
Normalized client directory and cached intelligence profile. De-duplicates client metadata across thousands of recurring incidents, tracks first/last observed activity, and manages MaxMind data expiration.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `INTEGER` / `BIGSERIAL` | **PRIMARY KEY**, Auto-inc | Unique surrogate entity ID. |
| `client_key` | `VARCHAR(64)` | **UNIQUE**, `NOT NULL` | Canonical client address or CIDR string. |
| `ip_version` | `SMALLINT` | `NOT NULL DEFAULT 4` | Protocol family (`4` or `6`). |
| `cidr_prefix` | `SMALLINT` | `NOT NULL DEFAULT 32` | Prefix bit length. |
| `ip_v4_start` / `ip_v4_end` | `BIGINT` | *Nullable* | Numeric IPv4 boundaries for fast SQL range containment queries. |
| `ip_v6_start` / `ip_v6_end` | `VARCHAR(16)` | *Nullable* | 16-byte IPv6 boundaries. |
| `subnet_group` | `VARCHAR(64)` | *Nullable* | Precalculated parent network (IPv4 `/24`, IPv6 `/64`). |
| `mmdb_network` | `VARCHAR(64)` | *Nullable* | Exact network block string returned by the offline MMDB reader. |
| `asn` | `BIGINT` | *Nullable* | Resolved Autonomous System Number. |
| `as_org` | `VARCHAR(255)` | *Nullable* | Resolved organization or ISP name. |
| `country_code` | `VARCHAR(2)` | *Nullable* | ISO two-letter country code. |
| `client_type` | `VARCHAR(32)` | `NOT NULL DEFAULT 'UNKNOWN'` | Resolved category (`DATACENTER`, `RESIDENTIAL`, `SEARCH_ENGINE`, `AI_CRAWLER`, etc.). |
| `tags` | `VARCHAR(255)` | *Nullable* | Supplemental flags (e.g. `GOOGLE_BOT`, `OPENAI_CRAWLER`, `TOR_EXIT`). |
| `enrichment_status`| `VARCHAR(16)` | `NOT NULL DEFAULT 'PENDING'` | Enrichment workflow status (`PENDING`, `RESOLVED`, `FAILED`). |
| `resolved_at` | `TIMESTAMP` | *Nullable* | Timestamp when enrichment was computed; checked against `ttl-days` for eviction. |
| `resolved_versions`| `VARCHAR(255)` | *Nullable* | Encoded feed versions at the time of resolution. |
| `first_seen` | `TIMESTAMP` | `NOT NULL DEFAULT CURRENT_TIMESTAMP` | Earliest time this entity appeared in any incident. |
| `last_seen` | `TIMESTAMP` | `NOT NULL DEFAULT CURRENT_TIMESTAMP` | Most recent time this entity appeared in any incident. |

* **Indexes:** `idx_entity_client_key`, `idx_entity_v4_range`, `idx_entity_v6_range`, `idx_entity_subnet_group`, `idx_entity_asn`, `idx_entity_client_type`, `idx_entity_enrichment_status`.

---

#### 5. `network_entity_match`
Many-to-many join table establishing explicit audit provenance between a `network_entity` and the intelligence rules/ranges that classified it.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `entity_id` | `INTEGER` / `BIGINT` | **PRIMARY KEY**, **FK** | References `network_entity(id)` with `ON DELETE CASCADE`. |
| `range_id` | `INTEGER` / `BIGINT` | **PRIMARY KEY**, **FK** | References `intel_range(id)` with `ON DELETE CASCADE`. |
| `matched_at` | `TIMESTAMP` | `NOT NULL DEFAULT CURRENT_TIMESTAMP` | Timestamp when the association was identified. |

---

#### 6. `intel_source`
Registry of external intelligence feeds, verified bot lists, MMDB databases, and static configuration lists. Powers the **Crawlers & Bots UI (`/crawlers`)**.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `source_key` | `VARCHAR(64)` | **PRIMARY KEY** | Unique identifier (e.g. `googlebot`, `bingbot`, `openai`, `torbulkexit`). |
| `source_type` | `VARCHAR(32)` | `NOT NULL` | Feed type: `FEED` (HTTP/HTTPS URL), `STATIC`, `MMDB`, or `MANUAL`. |
| `name` | `VARCHAR(128)` | `NOT NULL` | Human-readable name (e.g. `OpenAI Crawlers & GPTBot`). |
| `category` | `VARCHAR(32)` | `NOT NULL` | Assigned client classification (`SEARCH_ENGINE`, `AI_CRAWLER`, `TOR_EXIT_NODE`). |
| `url` | `VARCHAR(512)` | *Nullable* | Remote URL for automated polling and synchronization. |
| `version` | `BIGINT` | `NOT NULL DEFAULT 1` | Incremental version number incremented upon every feed content change. |
| `last_synced_at` | `TIMESTAMP` | *Nullable* | Timestamp of the last successful download and parse. |
| `status` | `VARCHAR(16)` | `NOT NULL DEFAULT 'PENDING'` | Operational status: `OK`, `SYNCING`, `ERROR`, or `PENDING`. |
| `prefix_count` | `INTEGER` | `NOT NULL DEFAULT 0` | Total number of active CIDR prefixes extracted from this source. |
| `last_error` | `TEXT` | *Nullable* | Error message or HTTP response failure details if synchronization failed. |

---

#### 7. `intel_range`
Specific IP network blocks (CIDRs) published by an `intel_source`.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `INTEGER` / `BIGSERIAL` | **PRIMARY KEY**, Auto-inc | Unique surrogate identifier for the IP prefix block. |
| `source_key` | `VARCHAR(64)` | `NOT NULL`, **FK** | References `intel_source(source_key)` with `ON DELETE CASCADE`. |
| `cidr` | `VARCHAR(64)` | `NOT NULL` | Canonical CIDR string (e.g. `66.249.64.0/19`, `2a03:2880::/32`). |
| `ip_version` | `SMALLINT` | `NOT NULL DEFAULT 4` | Protocol family (`4` or `6`). |
| `cidr_prefix` | `SMALLINT` | `NOT NULL DEFAULT 32` | CIDR mask prefix bit length. |
| `ip_v4_start` / `ip_v4_end` | `BIGINT` | *Nullable* | Numeric IPv4 boundaries for high-speed range queries. |
| `ip_v6_start` / `ip_v6_end` | `VARCHAR(16)` | *Nullable* | 16-byte IPv6 boundaries. |
| `asn` | `BIGINT` | *Nullable* | Explicit ASN associated with this range (if supplied by the feed). |
| `country_code` | `VARCHAR(2)` | *Nullable* | Country code associated with this range. |
| `category` | `VARCHAR(32)` | *Nullable* | Target classification category. |
| `label` | `VARCHAR(128)` | *Nullable* | Descriptive label or feed name. |
| `source_version` | `BIGINT` | `NOT NULL DEFAULT 1` | Source version during insertion (used for orphan detection during sync). |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT CURRENT_TIMESTAMP` | Record creation timestamp. |

* **Indexes:** `idx_intel_range_source (source_key)`, `idx_intel_range_v4 (ip_version, ip_v4_start, ip_v4_end)`, `idx_intel_range_v6 (ip_version, ip_v6_start, ip_v6_end)`.

---

#### 8. `asn_info`
Autonomous System catalog tracking organization names and datacenter / residential classifications.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `asn` | `BIGINT` | **PRIMARY KEY** | Autonomous System Number (e.g. `15169`, `32934`, `3320`). |
| `as_org` | `VARCHAR(255)` | *Nullable* | Organization or operator name (e.g. `GOOGLE`, `FACEBOOK`, `DTAG`). |
| `category` | `VARCHAR(32)` | `NOT NULL DEFAULT 'UNKNOWN'` | Classification (`DATACENTER`, `RESIDENTIAL`, `MOBILE`, `UNKNOWN`). |
| `category_source`| `VARCHAR(32)` | `NOT NULL DEFAULT 'DEFAULT'` | Classification rule source (`DEFAULT`, `CUSTOM_FILE`, `CONFIG`, `HEURISTIC`). |
| `updated_at` | `TIMESTAMP` | `NOT NULL DEFAULT CURRENT_TIMESTAMP` | Timestamp of the last catalog entry update. |

---

#### 9. `poll_event_log`
Audit trail recording every telemetry polling cycle across monitored Tomcat endpoints. Powers the **Event Log (`/poll-log`)**.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `INTEGER` / `BIGSERIAL` | **PRIMARY KEY**, Auto-inc | Unique surrogate log identifier. |
| `server_id` | `VARCHAR(100)` | `NOT NULL` | Server identifier matching `endpoint_heartbeats.server_id`. |
| `url` | `VARCHAR(255)` | `NOT NULL` | Target status URL queried. |
| `poll_time` | `TIMESTAMP` | `NOT NULL` | Timestamp when the poll was initiated. |
| `status` | `VARCHAR(20)` | `NOT NULL` | Execution outcome: `SUCCESS`, `WARNING`, or `ERROR`. |
| `http_status_code`| `INTEGER` | `DEFAULT 0` | HTTP response code received (e.g. 200, 401, 500, or 0 if unreachable). |
| `response_time_ms`| `INTEGER` | `DEFAULT 0` | HTTP round-trip latency in milliseconds. |
| `valves_polled` | `INTEGER` | `DEFAULT 0` | Number of distinct valve status payloads parsed. |
| `slots_ingested` | `INTEGER` | `DEFAULT 0` | Number of new or updated `slot_snapshots` written. |
| `events_ingested`| `INTEGER` | `DEFAULT 0` | Number of new or updated `client_events` written. |
| `details` | `TEXT` | *Nullable* | Diagnostic summary or structured telemetry details. |
| `error_message` | `TEXT` | *Nullable* | Full exception message or connection timeout details if failed. |

* **Indexes:** `idx_poll_log_time (poll_time DESC)`, `idx_poll_log_server_time (server_id, poll_time DESC)`, `idx_poll_log_status (status)`.

---

#### 10. `crawler_feeds` & `bot_ip_ranges` (Legacy Tables)
Maintained for backwards-compatibility from schema migration `V4`. In schema version `V5`, active threat intelligence lookups are conducted through the unified `intel_source` and `intel_range` tables.

---

### High-Performance IP Range Searching & Indexing

To evaluate whether a client IP falls within a specific CIDR block or arbitrary range, the database avoids expensive string parsing:

1. **IPv4 Numeric Conversion:**
   IPv4 addresses (`a.b.c.d`) are converted into unsigned 32-bit integers stored in 64-bit `BIGINT` columns (`ip_v4_start` and `ip_v4_end`). A point IP lookup or CIDR containment query is executed as a high-speed numerical range check:
   ```sql
   WHERE ip_version = 4
     AND :queryIpNumber BETWEEN ip_v4_start AND ip_v4_end
   ```
   Backed by composite B-Tree indexes (`idx_events_v4_range`, `idx_intel_range_v4`, `idx_entity_v4_range`), lookups complete in sub-millisecond time.

2. **IPv6 Binary Conversion:**
   IPv6 addresses are stored as fixed 16-character byte/hex representations in `VARCHAR(16)` (`ip_v6_start` and `ip_v6_end`), allowing lexical comparison operators (`BETWEEN :startHex AND :endHex`) using the corresponding B-Tree indexes.

3. **In-Memory Intel Registry (`IntelRegistry`):**
   In addition to SQL range indexes, the active bot/crawler IP blocks from `intel_range` are pre-compiled in memory using an interval tree index, enabling sub-microsecond classification during background ingestion without issuing database read queries.



