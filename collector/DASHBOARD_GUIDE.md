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
  * **Analytics (`/analytics`):** Dedicated visual telemetry cockpit, attack timelines, bot-mix composition, and 2D residential proxy cluster scatterplots.
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

### 3. Quick Visual Telemetry Summary
The fleet dashboard embeds a high-level visual summary of incoming traffic and rate-limiting blocks. For dedicated filter controls, interactive category focus pills, logarithmic zooming, and full residential cluster drilldowns, switch to the dedicated **[Visual Analytics & Cluster Forensics](/analytics)** view.

### 4. Quick Top Offending Clients (Fleet-wide)
A quick-look table showing top blocked IPs across all servers with one-click time horizon toggles (`1h`, `24h`, `7d`). For full forensic rollup analysis, use the dedicated Top Offenders view.

---

## Visual Analytics & Cluster Forensics (/analytics)

Accessible via `/analytics`. A dedicated visual observability cockpit designed for deep telemetry analysis, pattern recognition, and cluster forensics across long time horizons (`1h`, `6h`, `24h`, `7d`).

Powered by local, self-contained Chart.js (`chart.umd.min.js`), this view delivers high-throughput client-side rendering with logarithmic scaling, dynamic tooltips, and interactive click-to-filter drilldowns without external CDN or npm dependencies.

### 1. View Controls & Dedicated Filter Bar
Unlike search tables that focus on individual log records, the `/analytics` filter bar directly controls the aggregated time buckets and cluster matrices:
* **Server Node Selection:** Multi-select checkboxes to isolate specific Tomcat nodes or compare multi-region deployments.
* **Valve Selector:** Select a specific rate-limiter instance (`Primary-Limiter`, `Subnet-Guard`) or evaluate all valves combined.
* **Time Horizon Presets:**
  * `1 Hour`: High-resolution real-time monitoring of active incidents and sudden traffic surges.
  * `6 Hours`: Shift-level analysis covering recent peak or off-peak business cycles.
  * `24 Hours`: Comprehensive daily telemetry baseline identifying diurnal cycles and recurring scraper waves.
  * `7 Days`: Long-term trend analysis, baseline traffic growth, and persistent botnet activity.
* **Category Focus Pills:** Instantly isolate or highlight specific traffic classifications:
  * `All Categories`: Complete fleet-wide telemetry blend.
  * `Residential Proxies`: Focus on distributed residential ISP clusters and suspect botnets.
  * `Datacenter Scraping`: Highlight commercial cloud providers and VPS scrapers.
  * `Anonymizer / Tor`: Isolate Tor exit nodes and VPN proxies.
  * `Verified Crawlers`: Verify that legitimate search engines (Googlebot, Bingbot) and AI indexing bots operate unimpeded.
* **Reactive HTMX Integration:** Switching any filter triggers an asynchronous HTMX request (`hx-get="/fragments/analytics-overview"`) targeting `#analytics-container`. Chart.js instances are cleanly destroyed and re-instantiated with zero screen flicker and no full-page reloads.

---

### 2. Traffic & Attack Timeline (Stacked Bar / Area Chart)

Visualizes the temporal evolution of fleet traffic by stacking allowed requests against enforced rate-limiting blocks.

#### Chart Anatomy & Metrics:
* **X-Axis (Time):** Chronological bucket timestamps automatically adjusted to the selected horizon (minute intervals for `1h`, hourly intervals for `24h`/`7d`).
* **Y-Axis (Requests / Blocks):** Dynamic linear scale showing HTTP transaction volume per time slice.
* **Allowed Requests (Sky Blue / Cyan):** Total HTTP requests passed cleanly through the Valve to the upstream application.
* **Blocked Attacks (Vivid Danger Red):** HTTP 429 (`Too Many Requests`) blocks enforced by the Valve against abusive IPs or subnets.

#### Forensic Interpretation & Signature Patterns:
* **Organic Traffic Baseline:** A healthy application exhibits smooth diurnal curves (rising during business hours, dipping at night) where the red block line remains near zero or represents a tiny, stable fraction (< 0.5%).
* **Volumetric Layer-7 Flood (DDoS):** Marked by an abrupt vertical spike in red blocks while the blue line remains capped at the application's capacity threshold. The Valve successfully absorbs the spike, protecting backend Tomcat threads and database connection pools from exhaustion.
* **Scheduled Scraper Cron Job:** Sharp, periodic block spikes appearing at exact clock intervals (e.g., every hour at :00, or daily at midnight UTC). Typically driven by automated price scrapers, competitor bots, or vulnerability scanners.
* **Low-and-Slow Attack Waves:** Steady, elevated block rates persisting across days without dramatic volume peaks. Indicates distributed crawlers attempting to harvest data just below aggressive throttling limits.

---

### 3. Traffic Composition & Bot-Mix (Donut Chart)

Provides an immediate forensic breakdown of who is consuming your application's resources and what proportion of each category is being rate-limited.

#### Intelligence Categories:
1. **`SEARCH_ENGINE` (Green):** Verified search engine crawlers (Googlebot, Bingbot, Yandex) authenticated against official published IP ranges. Crucial for SEO health monitoring; block rates here should ideally be 0%.
2. **`AI_CRAWLER` (Purple):** Commercial AI scrapers and dataset miners (OpenAI GPTBot/ChatGPT-User, Anthropic ClaudeBot, PerplexityBot, Common Crawl, Bytespider).
3. **`DATACENTER` (Amber / Orange):** Traffic originating from cloud hosting facilities and VPS providers (AWS, Hetzner, DigitalOcean, OVH, Azure). Rarely genuine human end-users; high rates here indicate automated crawlers, headless browser automation, or attack vectors.
4. **`RESIDENTIAL` (Blue):** Legitimate consumer broadband and fiber ISPs (Comcast, Deutsche Telekom, Orange, Vodafone). High block rates in this category demand scrutiny (see Scatterplot below).
5. **`TOR_EXIT_NODE` (Deep Purple):** Relays from the public Tor anonymity network. Frequently abused for credential stuffing, automated registration, and vulnerability probes.
6. **`MOBILE` (Teal):** Cellular 4G / 5G carrier gateways (CGNAT). Because hundreds of mobile handsets share a single carrier IPv4 address, moderate block rates may occur during peak mobile usage.
7. **`PRIVATE_NET` (Slate Gray):** Internal RFC 1918 traffic (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.1`) from upstream load balancers, health checkers, or container meshes.
8. **`UNKNOWN` (Muted Gray):** Standard client traffic without specific intelligence tags or unclassified ASNs.

#### Interactive Forensic Capabilities:
* **Percentage Share:** Shows volume distribution at a glance.
* **Hover Tooltips:** Hovering over any segment displays total requests, blocked count, and the specific **Block Rate Percentage** for that category.
* **Click to Filter:** Clicking a donut segment automatically activates the corresponding category filter, narrowing down the timeline and cluster views.

---

### 4. Residential Proxy & Subnet Scatterplot (2D Cluster Visualizer)

The most advanced forensic instrument in the Anti-DoS Collector, engineered specifically to uncover distributed botnets and commercial proxy networks.

#### The "Residential Proxy" Evasion Dilemma:
Traditional rate-limiting relies on counting requests per IP address. Attackers bypass this by utilizing commercial residential proxy networks (e.g., Bright Data, Oxylabs, Smartproxy) consisting of millions of compromised consumer routers and IoT devices. An attacker distributes 100,000 scraping requests across 50,000 distinct IP addresses—each IP sends only 2 requests, easily staying below per-IP thresholds!

The Scatterplot solves this by mapping traffic aggregated across enclosing **Subnet Partitions** (`/24` for IPv4, `/64` for IPv6) over time.

#### Coordinate Space & Aesthetics:
* **X-Axis (Distinct Client IPs - Logarithmic):** Measures the width of the attack footprint within the subnet (from 1 IP up to 256 IPs for a `/24`).
* **Y-Axis (Average Requests per IP - Logarithmic):** Measures how aggressively each individual IP in that subnet acted.
* **Bubble Radius ($R$):** Proportional to the total aggregated volume sent by the subnet:
  $$\text{Radius} = \max\left(4, \, \min\left(28, \, \frac{\sqrt{\text{Total Requests}}}{2}\right)\right)$$
* **Logarithmic Scaling:** Employs logarithmic $X$ and $Y$ scales so that single rogue IPs ($X=1, Y=10{,}000$) and massive distributed clusters ($X=200, Y=3$) are visible simultaneously without clustering at the axes.

#### Cluster Quadrant Analysis:
```
           High Avg Reqs / IP
                   ▲
   [Traditional Brute-Force]   │   [Heavy Datacenter Scraper]
   Few IPs, huge volume each   │   Dense subnet, high throughput
   (Single-IP limiter catches) │   (Easy to block via /24 CIDR)
───────────────────────────────┼───────────────────────────────
   [Organic Consumer Noise]    │   🔴 [DISTRIBUTED RESIDENTIAL BOTNET]
   Few IPs, low volume         │   Massive number of distinct IPs,
   (Normal browsing)           │   each staying below per-IP limits!
                   ▼
           Low Avg Reqs / IP ────────► High Distinct IPs
```

* **Quadrant 1 (Top-Left - Traditional Single-Source Floods):** Low distinct IPs ($X \le 2$), very high requests per IP ($Y > 500$). Handled effectively by standard Anti-DoS Valve client IP limits.
* **Quadrant 4 (Bottom-Right - Distributed Botnets & Rotating Proxies):** High distinct IPs ($X \ge 10$), low requests per IP ($Y < 50$). **This is the smoking gun of residential proxy attacks.** Even though no single IP exceeded rate limits, the subnet as a whole executed a synchronized distributed campaign!

#### Cluster Risk Ratings & Color Legend:
* 🔴 **Crimson Red (`CRITICAL` / `HIGH`):** Heuristically flagged **Residential Proxy Cluster**. High distinct IP count in consumer ISP subnets with low average requests per IP.
* 🟠 **Amber Orange (`MEDIUM`):** Datacenter / Cloud scraper cluster. Subnets originating from hosting ASNs.
* 🟣 **Purple (`ELEVATED`):** Tor exit nodes or commercial VPN gateways.
* 🟢 **Emerald Green (`BENIGN`):** Verified crawler subnets (e.g. Googlebot IP ranges).
* 🔵 **Sky Blue (`LOW`):** Standard unclassified or mobile CGNAT traffic.

#### Interactive Click-to-Drilldown:
Clicking any bubble in the scatterplot instantly captures the clicked subnet prefix (e.g., `198.51.100.0/24`) and navigates directly to:
```
/offenders?subnet=198.51.100.0/24&groupBy=ROLLUP
```
This automatically displays all member IPs, block counts, and Autonomous System details, providing immediate evidence for firewall rules or Valve configuration tuning.

---

### 5. Practical Investigation Workflows

#### Workflow A: Unmasking a Stealth Residential Scraping Wave
1. Navigate to `/analytics` and select the **24 Hours** or **7 Days** time horizon.
2. Click the **Residential Proxies** focus pill.
3. Observe the **Residential Proxy Scatterplot**: Look for crimson bubbles positioned in the bottom-right quadrant ($X \ge 10\text{ IPs}$, $Y \le 30\text{ reqs/IP}$).
4. Hover over the bubble to view the tooltip: Subnet CIDR, Autonomous System (e.g., `AS7922 Comcast`), total request volume, and heuristic risk rating.
5. Click the bubble: The dashboard transfers you to `/offenders` filtered for that subnet.
6. Verify the incident timeline in `/events`. If abusive intent is confirmed, add the subnet prefix to your perimeter WAF or tune the Valve's `retainedSubnetSlots` threshold.

#### Workflow B: Verifying Zero Disruption to Search Engines (SEO Safeguard)
1. Navigate to `/analytics` and select **7 Days**.
2. Click the **Verified Crawlers** focus pill.
3. In the **Traffic & Attack Timeline**, inspect the red blocked bars. Blocked requests for verified crawlers should be zero or negligible.
4. If blocks appear, check the **Donut Chart** block rate for `SEARCH_ENGINE`.
5. Drill down into `/events?clientType=SEARCH_ENGINE` to verify whether legitimate Googlebot or Bingbot IPs are triggering rate limits, and adjust Valve `clientThreshold` or whitelist settings accordingly.

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
* **Table Record Counts:** Real-time row counts for all database tables:
  * `slot_snapshots`: Historical telemetry slot summaries per valve.
  * `client_events`: Recorded client incidents (both blocked rate-limit events and high-volume active clients).
  * `client_subnet_rollups`: Aggregated subnet-level time-bucket records (/24 for IPv4, /64 for IPv6). Generated periodically for completed time windows (default: 60 minutes).
  * `network_entity`: Normalized directory of enriched client IPs and subnets with ASN, geolocation, and threat classifications.
  * `poll_event_log`: Background ingestion audit diagnostics.
  * `intel_range`: Verified CIDR intelligence ranges for legitimate crawlers, commercial AI scrapers, and Tor exit relays.
  * `crawler_feeds`: Registered crawler intelligence feeds and sync states.

### 2. Polling Rules & Concurrency
* **Polling Interval:** Global frequency of status polling (default: 15s).
* **Virtual Threads Polling:** In Java 21, fleet polling executes across lightweight virtual threads, ensuring slow endpoints never bottleneck the fleet.
* **Config File Location:** Displays the loaded configuration path (e.g. `/etc/antidos/collector-config.yaml`).

### 3. Telemetry Cascade & Rollup Rules
* **Rollup Window Interval:** Bucketing granularity for background aggregation (default: 60 minutes). Scheduled background aggregation evaluates completed windows every 15 minutes; in-flight traffic for the current ongoing window is preserved in `client_events` and committed to `client_subnet_rollups` once the window closes.
* **Lookback Horizon:** Number of past hours evaluated during scheduled rollups (default: 6 hours catch-up window).
* **Retention Cleanup:** Daily cleanup at 03:30 AM purging rollups older than the configured retention horizon (default: 180 days).

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
