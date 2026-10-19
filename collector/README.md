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
  * Cross-navigation drill-down from Top Offenders directly into filtered incident logs.
* **Built-in Demo Mode (Out-of-the-Box Exploration):** Launch the collector with zero configuration against simulated multi-node Valve endpoints (Edge EU, API Gateway under active attack, Staging Node with telemetry diagnostics, and realistic ASN/Country profiles).
* **CLI Onboarding Tool:** Built-in command to test connectivity, verify tokens, and generate ready-to-use configuration blocks.

---

## Zero-Configuration Demo Mode

To explore the dashboard and telemetry engine without configuring or connecting any live Tomcat servers, launch the collector in **Demo Mode**:

```bash
# Using the Fat-JAR:
java -jar collector/target/anti-dos-collector-1.7.1.jar demo

# Or using Maven:
mvn spring-boot:run -pl collector -Dspring-boot.run.arguments="demo"
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
This produces the executable Spring Boot JAR in `collector/target/anti-dos-collector-1.7.1.jar`.

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
java -jar collector/target/anti-dos-collector-1.7.1.jar test-endpoint \
  --url "http://localhost:8080/antidos-status" \
  --token "secretToken1" \
  --name "Web-Node-1"
```

### 4. Run the Collector
```bash
java -jar collector/target/anti-dos-collector-1.7.1.jar
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
# Create dedicated system user
sudo useradd -r -s /bin/false -d /var/lib/antidos -c "Anti-DoS Collector Service" antidos || true

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

  # Monitored Tomcat server endpoints
  endpoints:
    - name: "Prod-Web-01"
      url: "https://web01.internal.example.com/antidos-status"
      token: "yourSecureStatusToken1"
      poll-intermediate-slots: false
      enabled: true

    - name: "Prod-Web-02"
      url: "https://web02.internal.example.com/antidos-status"
      token: "yourSecureStatusToken2"
      poll-intermediate-slots: false
      enabled: true

  enrichment:
    enabled: true
    asn-database-path: "/var/lib/antidos/dbip-asn-lite.mmdb"
    country-database-path: "/var/lib/antidos/dbip-country-lite.mmdb"
    custom-hosting-asns-file: "/etc/antidos/custom-hosting-asns.txt"
```

> **Note on Auto-Discovery:** The Collector automatically looks for `/etc/antidos/collector-config.yaml` and `${user.home}/.antidos/collector-config.yaml` upon startup. No extra `--spring.config.additional-location` flag is required.

#### Step 3: Test Endpoint Connectivity via CLI
Before starting the background service, verify network connectivity and token authentication against your live Tomcat nodes:
```bash
java -jar collector/target/anti-dos-collector-1.7.1.jar test-endpoint \
  --url "https://web01.internal.example.com/antidos-status" \
  --token "yourSecureStatusToken1" \
  --name "Prod-Web-01"
```

#### Step 4: Deploy the Fat-JAR & Install systemd Service
Deploy the packaged Fat-JAR:
```bash
sudo cp collector/target/anti-dos-collector-1.7.1.jar /opt/antidos-collector/anti-dos-collector.jar
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
java -jar collector/target/anti-dos-collector-1.7.1.jar
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
  slow-poll-threshold-ms: 1000  # Latency threshold before marking poll status as WARNING (default: 1000 ms)
```

---

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
    asn-database-path: "/var/data/dbip-asn-lite.mmdb"         # or /usr/share/GeoIP/GeoLite2-ASN.mmdb
    country-database-path: "/var/data/dbip-country-lite.mmdb" # or /usr/share/GeoIP/GeoLite2-Country.mmdb
    custom-hosting-asns-file: "custom-hosting-asns.txt"      # optional custom ASN overlay
    crawler-sync-enabled: true                               # automated search engine & AI bot feed sync
    crawler-sync-cron: "0 0 4 * * *"                         # daily at 04:00 AM
```

Or via environment variables:
```bash
export COLLECTOR_ENRICHMENT_ASN_DATABASE_PATH="/var/data/dbip-asn-lite.mmdb"
export COLLECTOR_ENRICHMENT_COUNTRY_DATABASE_PATH="/var/data/dbip-country-lite.mmdb"
```

### 3. How Enrichment Operates

* **Zero-Ops Fallback:** If no MMDB database paths are configured, the collector boots immediately without errors. Verified Search Engine/AI Bot detection and Private Network (`10.68.*.*`, `192.168.*.*`, IPv6 ULA) classification still operate out-of-the-box.
* **Asynchronous Background Processing:** Poller threads write incident events with status `PENDING` without blocking or polling latency. The `BackgroundEnrichmentWorker` resolves ASNs, Geolocation, and Client Types asynchronously in small batches on Java 21 Virtual Threads.
* **Layered Hosting ASN Overlay:** Shipped defaults (`classpath:asns/default-hosting-asns.txt`) can be customized via `custom-hosting-asns.txt` without Git checkout conflicts:
  * `+12345` (force ASN 12345 to be classified as Datacenter/Hosting)
  * `-24940` (remove Hetzner from Datacenter list, classifying it as Residential)
* **Crawler Feed Sync & Management UI (`/crawlers`):**
  * Automated periodic sync fetches official JSON IP ranges for Googlebot, Bingbot, OpenAI GPTBot, ChatGPT-User, etc.
  * Trigger immediate manual syncs per feed or globally via the HTMX buttons in the `/crawlers` dashboard.
  * Pruning: Removed feed configurations automatically trigger an orphan purge from the database.

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


