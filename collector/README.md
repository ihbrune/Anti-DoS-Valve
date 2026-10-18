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
java -jar collector/target/anti-dos-collector-1.7.0.jar demo

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
This produces the executable Spring Boot JAR in `collector/target/anti-dos-collector-1.7.0.jar`.

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
java -jar collector/target/anti-dos-collector-1.7.0.jar test-endpoint \
  --url "http://localhost:8080/antidos-status" \
  --token "secretToken1" \
  --name "Web-Node-1"
```

### 4. Run the Collector
```bash
java -jar collector/target/anti-dos-collector-1.7.0.jar
```
Open your browser at **`http://localhost:8090`** to access the Fleet Dashboard.

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
java -jar collector/target/anti-dos-collector-1.7.0.jar
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

