# Anti-DoS Collector: Dashboard & Forensics Guide

This guide is designed for **Security Analysts, Incident Responders, and Web Application Owners** monitoring web traffic and mitigating Denial-of-Service (DoS) and scraping incidents using the Anti-DoS Collector.

---

## Architecture of the Dashboard & Navigation

The Collector interface is built around high-throughput, real-time observability without heavy frontend overhead.

### Key Global Controls:
* **Pulse Auto-Refresh Indicator:** The pulsing green dot indicates active background telemetry updates (every 10 seconds via HTMX).
* **Theme Switcher (`☀️ / 🌙`):** Instant switch between tailored Dark and Light modes with anti-FOUC persistence across sessions.
* **Contextual Help Drawers (`[?] Guide`):** Every screen features an in-page slide-over drawer that explains the active view's filters, data models, and forensic interpretations without losing current search queries.
* **Top Navigation Bar:**
  * **Dashboard (`/`):** Real-time fleet overview, health cards, and top offenders.
  * **Top Offenders (`/offenders`):** Multi-server aggregation ranking, Subnet Rollup (`/24` & `/64`), and ASN cluster detection.
  * **Incident Explorer (`/events`):** High-resolution log search with CIDR subnets, exact time horizons, and classification tags.
  * **Event Log (`/poll-log`):** Background collection audit trail, latency tracking, and automatic recovery events.
  * **Crawlers & Bots (`/crawlers`):** Official search engine and AI scraper IP ranges with synchronization metrics.
  * **System & Config (`/system`):** Retention policies, database internals, polling cascades, and manual maintenance triggers.
  * **Help & Guide (`/help`):** Full offline documentation repository.

---

## Fleet Overview Dashboard

Accessible via `/`. The central command center summarizing telemetry across all connected Tomcat servers and Anti-DoS Valve instances.

### 1. Fleet KPI Summary Cards
* **Total Requests (24h):** Aggregate HTTP requests processed by all monitored valves within the last 24 hours.
* **Blocked Incidents (24h):** Total count of HTTP 429 rate-limit blocks enforced across the fleet.
* **Block Rate (%):** Proportion of requests blocked; sudden spikes above baseline indicate ongoing volumetric or distributed attacks.
* **Monitored Nodes:** Online server instances vs. total configured endpoints.

### 2. Monitored Server Nodes Grid
Each card represents a distinct Tomcat instance:
* **Health Badge (`ONLINE` / `OFFLINE`):** Node responsiveness detected via background polling.
* **Uptime & Latency:** Response time for the `/antidos-status` JSON handshake.
* **Valve Breakdown:** Lists each active valve within that node, its current operating mode (`BLOCKING` or `MARKING`), slot length, and request throughput.
* **Direct Navigation:** Click any server card header to open the dedicated **Server Node Detail View** (`/server/{serverId}`).

### 3. Visual Telemetry & Attack Forensics Card
A high-resolution visualization suite powered by standalone Chart.js:
* **Traffic & Attack Timeline (Stacked Bar / Area):** Visualizes incoming request volume split into allowed requests (sky blue) and HTTP 429 blocked attacks (vivid danger red) over time (`1h`, `24h`, `7d`).
* **Traffic Composition & Bot-Mix Donut:** Breaks down fleet traffic by verified category (Search Engines, AI Crawlers, Datacenter / Cloud, Residential ISP, Tor Anonymizers, Mobile Cellular, and Standard Clients) with percentage shares and block rates.
* **Residential Proxy & Subnet Scatterplot (Cluster Forensics):** Maps subnet partitions on a 2D logarithmic coordinate system:
  * **X-Axis:** Unique client IPs in the subnet.
  * **Y-Axis:** Average requests per IP address.
  * **Bubble Radius:** Proportional to total request volume.
  * **Color Coding:** Outlines residential proxy clusters (red), datacenter scrapers (amber), Tor exit nodes (purple), and benign crawlers (green).
  * **Interactive Drill-Down:** Clicking any bubble instantly filters the Top Offenders table for that specific CIDR prefix.

### 4. Quick Top Offending Clients (Fleet-wide)
A quick-look table showing top blocked IPs across all servers with one-click time horizon toggles (`1h`, `24h`, `7d`). For full forensic rollup analysis, use the dedicated Top Offenders view.

---

## Server Node Detail View

Accessible by clicking a server name or visiting `/server/{serverId}`.

* **Node Telemetry Summary:** Displays host URL, online state, detected JVM/Tomcat environment, and slot durations.
* **Valve Pipeline Status:** Details each valve configured in Tomcat's `server.xml` pipeline, including threshold ratios, retained former request weighting, and active memory counters.
* **Node-Specific Recent Incidents:** Lists the most recent rate-limiting events originating specifically from this node with one-click drilldown into the Incident Explorer.

---

## Top Offender Analytics & Subnet Forensics

Accessible via `/offenders`. The premier forensic tool for identifying volumetric scrapers, brute-force bots, and distributed proxy clusters.

### 1. Aggregation Modes
* **Individual IP Mode (`groupBy=NONE`):**
  Ranks single IP addresses by total block count. Ideal for catching aggressive single-source crawlers, vulnerability scanners, or script kiddies.
* **Subnet Rollup Mode (`groupBy=ROLLUP`):**
  Aggregates incidents into enclosing network boundaries:
  * IPv4 addresses are grouped into standard **`/24` subnets** (256 addresses).
  * IPv6 addresses are grouped into **`/64` subscriber blocks**.
  * **Why Subnet Rollup is essential:** Modern botnets rotate between dozens or hundreds of sequential IP addresses within the same cloud or residential subnet. Individual IP counters stay below rate-limit thresholds, but Subnet Rollup instantly reveals the cluster.
* **ASN Rollup Mode (`groupBy=ASN`):**
  Groups all incidents by Autonomous System Number (e.g., `AS16509 Amazon.com`, `AS14061 DigitalOcean`, `AS8075 Microsoft`).
  Unmasks whether an attack wave originates from bulletproof hosters, cheap cloud providers, or compromised consumer ISPs.

### 2. Rotating Proxy Cluster Detection
When analyzing subnets or ASNs, the system automatically runs heuristic cluster analysis:
* **Cluster Badge (`⚡ ROTATING PROXY CLUSTER`):** Highlighted in warning amber when a high ratio of distinct client IPs within a single `/24` or ASN generate synchronized bursts.
* **Attribution Badges:** Each offender row displays:
  * Autonomous System Number & Organization Name.
  * ISO Country Code & Flag.
  * Client Type classification tag (`DATACENTER`, `RESIDENTIAL`, `AI_CRAWLER`, etc.).

### 3. Forensic Drilldown
Clicking the **`Incident Explorer →`** action button on any offender row automatically transitions to `/events`, pre-populating the search filter with the exact IP or CIDR mask (`/24` or `/64`) for high-resolution event inspection.

---

## Incident Explorer & Forensic Log Search

Accessible via `/events`. Provides deep-dive, granular search across every recorded rate-limiting event stored in the Collector database.

### 1. Multi-Dimensional Filter Controls
* **Server Nodes:** Checkboxes to isolate or combine specific Tomcat servers.
* **Valve Instances:** Select specific rate-limiter valves (e.g. `Primary-Limiter` vs. `Subnet-Guard`).
* **Time Horizon:**
  * Quick presets: `1 Hour`, `6 Hours`, `24 Hours`, `7 Days`.
  * **Custom Exact Range:** Native date-time pickers allowing exact historical incident forensics.
* **Client IP / CIDR Search:**
  * Matches individual IPv4/IPv6 addresses (e.g., `198.51.100.42`).
  * Matches CIDR prefix ranges (e.g., `198.51.100.0/24` or `2001:db8::/32`).
  * Partial substring search for quick lookup.
* **Client Type Filter:**
  Multi-select pills to filter by threat categorization: `Datacenter`, `Residential`, `Search Engine`, `AI Crawler`, `Tor Exit Node`, `Mobile`, `Private Network`, `Unknown`.
* **ASN Filter:** Filter directly by ASN number or provider name (e.g., `AS13335` or `Cloudflare`).

### 2. High-Performance Server-Side Pagination
Events are streamed with configurable limits (`25`, `50`, `100`, `250`) and offset pagination. The URL dynamically reflects active filters via HTMX `hx-push-url="true"`, allowing links to specific forensic queries to be bookmarked or shared with team members.

---

## Verified Crawlers & AI Bot Manager

Accessible via `/crawlers`. Maintains verified IP intelligence feeds for legitimate web indexing bots and commercial AI scrapers.

### 1. Categories Managed
* **Search Engine Bots:** Googlebot, Bingbot / MSN. Essential for public SEO; false-positive blocks can harm search visibility.
* **AI Scrapers:** OpenAI (GPTBot, ChatGPT-User), Anthropic ClaudeBot, PerplexityBot, Common Crawl, Bytespider.
* **Tor Exit Nodes:** Real-time directory of active Tor network relays.

### 2. Operational Features
* **Feed Status & IP Range Counts:** Displays active status, total IPv4 and IPv6 CIDR blocks registered, and last sync timestamp.
* **Automatic Daily Synchronization:** Scheduled background tasks pull updated official JSON feeds every 24 hours.
* **Manual "Sync All Feeds" Trigger:** Immediately contacts official feed URLs and refreshes in-memory threat intelligence.
* **Automatic Orphan Pruning:** Ensures decommissioned crawler IP ranges are automatically evicted from the database upon synchronization.

---

## Data Collection Event Log & Audit Diagnostics

Accessible via `/poll-log`. Provides full operational observability into the Collector's background ingestion pipeline.

### 1. Diagnostic Metrics
* **Total Polls (24h):** Number of polling cycles executed across all endpoints.
* **Success Rate (%):** Reliability index of telemetry communication.
* **Slow Poll Warnings:** Alerts when `/antidos-status` JSON response latency exceeds the warning threshold (default: 1,000 ms).
* **Recovery Catches:** Count of automatic gap-recovery operations executed.

### 2. Automatic Telemetry Recovery
If a monitored Tomcat instance is temporarily unreachable or restarted:
1. The Collector logs a `WARNING` or `ERROR` event in the audit log.
2. Upon restored connectivity, the Collector queries the missing slot keys (`slot=<key>`).
3. Telemetry gaps are seamlessly backfilled without data loss, logging a `RECOVERY` audit entry.

---

## System Status & Configuration

Accessible via `/system`. The administrative and telemetry health center of the Collector service.

### 1. Runtime & Database Telemetry
* **Uptime & JVM Memory:** Running instance duration and JVM heap allocation.
* **Database Engine & File Storage:** Active engine (SQLite or PostgreSQL), disk space consumption, WAL journal status, and sanitized JDBC connection string.
* **Flyway Migration Version:** Current schema version and applied migration scripts.
* **HikariCP Connection Pool:** Active, idle, and maximum database connections.
* **Table Record Counts:** Real-time row counts for `slot_snapshots`, `blocked_client_events`, `subnet_rollup_buckets`, and `poll_event_log`.

### 2. Polling Rules & Concurrency
* **Polling Interval:** Global frequency of status polling (default: 15s).
* **Virtual Threads Polling:** In Java 21, fleet polling executes across lightweight virtual threads, ensuring slow endpoints never bottleneck the fleet.
* **Config File Location:** Displays the loaded configuration path (e.g. `/etc/antidos/collector-config.yaml`).

### 3. Telemetry Cascade & Rollup Rules
* **Rollup Window Interval:** Bucketing granularity for background aggregation (e.g. 15, 30, or 60 minutes).
* **Lookback Horizon:** Number of past days evaluated during scheduled rollups (default: 7 days).
* **Min Incident Threshold:** Noise filter threshold preventing single isolated blocks from cluttering subnet aggregations.

### 4. Threat Intelligence & MMDB Status
* **ASN Lookup Engine:** GeoLite2 / MaxMind ASN database path and status.
* **Country Lookup Engine:** GeoLite2 Country database path and status.
* **Intel Registry:** Number of active CIDR rules cached in RAM.
* **Custom ASN Overlay:** Location and state of custom datacenter ASN definitions (`custom-datacenter-asns.txt`).

### 5. Operational Maintenance Triggers
Admins can trigger asynchronous maintenance actions directly from the web interface:
* **Run Subnet Rollup Now:** Manually recalculates persistent subnet aggregations across recent events.
* **Refresh Threat Intel:** Triggers an immediate crawler feed sync and IP classification cache reload.
* **Optimize / Vacuum DB:** Executes SQLite `PRAGMA incremental_vacuum` or `OPTIMIZE` to reclaim unallocated disk blocks and refresh B-tree statistics.
* **Force Fleet Poll:** Triggers an immediate polling sweep across all monitored servers.
* **Reset Demo Data (Demo Mode Only):** Re-seeds the demo database with clean, realistic 7-day telemetry curves.

---

## Threat Intelligence Badges & Classifications Reference

| Badge | Client Type | Forensic Meaning & Recommended Action |
|---|---|---|
| `DATACENTER` | Cloud / Hosting Provider | Traffic originating from AWS, Hetzner, DigitalOcean, OVH, etc. Rarely genuine human browsing. High risk of automated scraping or attacks. Safe to block or apply strict thresholds. |
| `RESIDENTIAL` | Consumer Broadband / Fiber | Real home internet connections (Comcast, Deutsche Telekom, Orange). If generating high block counts, suspect malware compromise or residential proxy botnets (check for Rotating Proxy Cluster badge). |
| `SEARCH_ENGINE` | Verified Search Bot | Verified Googlebot, Bingbot, or Yandex crawler. Ensure rate-limit rules do not unintentionally suppress indexing. |
| `AI_CRAWLER` | AI Model Scraper | Commercial AI scrapers (OpenAI GPTBot, ClaudeBot, Perplexity). Block or rate-limit if intellectual property protection or bandwidth preservation is desired. |
| `TOR_EXIT_NODE` | Tor Anonymizer | Traffic from public Tor exit relays. Often used to circumvent IP blocks or conceal threat actor origins. |
| `MOBILE` | Cellular 4G / 5G Carrier | Mobile network gateways (CGNAT). Multiple distinct cellular users share single public IPv4 addresses; exercise caution when applying permanent IP bans. |
| `PRIVATE_NET` | RFC 1918 / Local IP | Local internal traffic (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.1`). Typically health checks, load balancers, or internal services. |
| `UNKNOWN` | Unclassified | IP address with no matching intelligence feeds or ASN data. |
