# Release Notes – Version 2.1.0

Version 2.1.0 extends the closed-loop defense architecture of the Anti-DoS-Valve ecosystem into the **application and fingerprint layer**, introducing **Dynamic User-Agent Signature Mitigation**, **Composite Forensic Priority Request Sampling**, **Interactive Block Diagnosis for Support & SOC Teams**, **Endpoint & URL Hotspot Analytics**, **Persistent User-Agent Intelligence Memory**, and **Zero-Dependency JVM/Tomcat Host Resource Telemetry**.

---

## Highlights

### 🛡️ Dynamic User-Agent Signature Mitigation & Bypass Controls *(Valve & Collector)*
In addition to IP and CIDR subnet blocking, Version 2.1.0 enables fleet-wide runtime mitigation of abusive User-Agent signatures without restarting Apache Tomcat:

- **O(1) 32-Bit FNV-1a User-Agent Blocking (`AntiDoSDynamicBlockRegistry`):**
  - Valves match incoming User-Agent headers against active dynamic UA rules using a fast, lock-free 32-bit folded FNV-1a hash lookup (`uaHash32`) guarded by a volatile fast-path flag (`hasActiveUaBlocks`).
  - Supports runtime management via HTTP `POST` actions: `upsertua`, `removeua`, `replaceua`, `clearua`, and atomic combined CIDR + UA synchronization via `replace`.
- **Three-Layer False-Positive Immunity (Automatic Bypass):**
  - Even when a request's User-Agent matches an active block rule (for example, when scrapers spoof a common browser signature), the Valve automatically bypasses the UA block and records a `bypassedRequests` hit if the client is:
    1. **Authenticated (`isAuthenticated`):** Carries a verified login session cookie, OR
    2. **Verified Returning Visitor (`isReturningVisitor && !uaMismatch`):** Presents an aged, cryptographically valid visitor token cookie without User-Agent tampering, OR
    3. **IP-Bypassed (`mitigationBypassPrivateIPs` / `mitigationBypassIPs`):** Originates from an exempt internal network or trusted gateway IP.
- **Dynamic Mitigation IP Bypass Configuration (`Valve`):**
  - `mitigationBypassPrivateIPs` (default: `true`): Automatically exempts private, loopback, link-local, and IPv6 ULA addresses (RFC 1918, RFC 4193, etc.) from dynamic CIDR and User-Agent mitigation rules while keeping them subject to local sliding-window rate limits.
  - `mitigationBypassIPs`: Regular expression exempting specific public gateways (such as corporate VPNs or campus NAT addresses) from remotely pushed dynamic blocks without granting unconditional `alwaysAllowedIPs` rate-limit immunity.
- **Collector UA Mitigation Cockpit & Drilldown Actions:**
  - Operators can block, extend, or revoke User-Agent signatures across the entire fleet directly from the Mitigation Cockpit or via 1-click shortcuts in the User-Agent Drilldown Modal (Flyway migration V38).

---

### 🩺 Interactive Block Diagnosis & Support Lookup Engine *(Collector)*
When a user or customer reports being unable to access an application, support and SOC analysts can now pinpoint the exact cause in seconds via the **Block Diagnosis** engine (`/events` & `/events/diagnose`):

- **7-Layer Forensic Correlation (`BlockDiagnosisService`):**
  - Accepts a client IPv4/IPv6 address, an optional incident timestamp (with configurable lookback window), and an optional User-Agent string.
  - Automatically cross-checks the inquiry against:
    1. **Whitelist & Bypass Rules:** Evaluates `alwaysAllowedIPs`, `alwaysAllowPrivateIPs`, `mitigationBypassPrivateIPs`, and `mitigationBypassIPs` across all monitored Valves (Flyway migration V41).
    2. **Active & Historical Dynamic CIDR Rules:** Performs exact binary IPv4/IPv6 CIDR containment matching against active and expired subnet blocks.
    3. **Active & Historical Dynamic User-Agent Rules:** Evaluates 32-bit FNV-1a hash matches and explains whether cookie/session bypasses applied.
    4. **Direct Valve Client Events:** Searches sliding-window rate-limit blocks (`BLOCKED`), simulation marks (`MARKED`), and unblocked high-activity counters (`ALLOWED`).
    5. **Aggregated Subnet Rollups:** Correlates `/24` (IPv4) and `/64` (IPv6) hourly rollups for collateral neighborhood activity.
    6. **User-Agent Intelligence Memory:** Evaluates the reported User-Agent for bot heuristics, forged browser builds, and historical incident rates.
    7. **Valve Guardrail Context:** Summarizes effective thresholds (`allowedRequestsPerSlot`, `slotLength`, `httpStatusCode`) on the affected nodes.
- **Actionable Verdicts:**
  - Generates a structured diagnostic report with a clear status verdict (`CONFIRMED_BLOCK`, `HISTORICAL_BLOCK`, `POSSIBLE_SUBNET_OR_UA_MATCH`, `BYPASSED_OR_WHITELISTED`, `NO_EVIDENCE_FOUND`), human-readable root-cause explanation, and concrete remediation steps.

---

### 🎯 Composite Forensic Priority Request Sampling *(Valve & Collector)*
To ensure that forensic request samples captured on active or blocked counters always reflect the most security-relevant traffic rather than background static assets, `AntiDoSCounter` now implements a **12-level composite priority scoring model (`0..11`)**:

$$\text{Priority} = (\text{SemanticCategory} \times 3) + \text{SuspicionTier}$$

- **Major Tier – Semantic Endpoint Category (`0..3`, weight $\times 3$):**
  - `3` (**Mutating Actions**): `POST`, `PUT`, `DELETE`, `PATCH` requests.
  - `2` (**Content, Routes, Documents & APIs**): Extensionless routes (e.g. `/portal/course/catalog`, `/api/v1/search`) and dynamic/document extensions (`.jsp`, `.html`, `.json`, `.xml`, `.pdf`, `.csv`, `.zip`, etc.).
  - `1` (**Media & Images**): `.png`, `.jpg`, `.svg`, `.webp`, `.mp4`, etc.
  - `0` (**Static Frontend Assets**): `.js`, `.css`, `.woff2`, `.ico`, `.map`, etc.
- **Minor Tier – Client Suspicion Sub-Tier (`0..2`, within the same semantic category):**
  - `+2` (**Unauthenticated & No Visitor Cookie**): Highest forensic interest (cookieless bots, headless scrapers, raw `curl`/Python clients).
  - `+1` (**Unauthenticated Returning Visitor**): Anonymous browser carrying a valid visitor token cookie.
  - `+0` (**Authenticated Session**): Logged-in user with a verified session cookie.
- **Lock-Free Atomic Sample Upgrading (`recordSampleIfHigherPriority`):**
  - Uses a lock-free `VarHandle` compare-and-set loop to upgrade a counter's captured `SampleRequest` whenever a strictly higher-priority request arrives during the slot.
  - Prevents legitimate logged-in users or static asset requests from masking unauthenticated scraper hits within shared `/24` subnet counters.
- **Returning Visitor Sample Telemetry (`sampleReturningVisitor`):**
  - Request sample snapshots now record whether the sampled request carried a valid visitor cookie (`sampleReturningVisitor`), exposed in Valve JSON status, OpenAPI 3.1 specifications, and Collector `client_events` (Flyway migration V36).

---

### 🌐 Endpoint Forensics & URL Hotspot Analytics (`tab=endpoints`) *(Collector)*
The Analytics dashboard now includes a dedicated **Endpoints** tab (`/?tab=endpoints`) and REST API (`/api/v1/analytics/endpoints`) to identify which application routes are targeted by scrapers and rate-limiting incidents:

- **Hourly Endpoint Rollups (`EndpointAnalyticsService`, Flyway V40):**
  - Aggregates sampled request URIs and HTTP methods into hourly buckets (`endpoint_rollups`), tracking total sampled volume, blocked/marked request counts, incident rates, authenticated vs. returning visitor shares, distinct ASNs, and distinct User-Agents.
- **Semantic Category Filtering & KPIs:**
  - Filter hotspots by semantic category (`MUTATING`, `CONTENT_API`, `MEDIA`, `STATIC_ASSET`), server node, or search term.
- **Interactive Endpoint Drilldown Modal:**
  - Clicking any endpoint opens a forensic modal displaying its 24-hour traffic and incident timeline, top originating Autonomous Systems, and top User-Agents hitting that specific route.

---

### 🧠 Persistent User-Agent Intelligence Memory & Forged Browser Detection *(Collector)*
User-Agent analysis has been expanded from ephemeral 24-hour window queries to a persistent intelligence catalog (Flyway migration V35):

- **Long-Term User-Agent Memory (`UserAgentMemoryService`):**
  - Continuously tracks every observed User-Agent signature in `user_agent_memory` and `user_agent_hourly_rollups`, retaining first-seen and last-seen timestamps, cumulative request and incident counters, authentication ratios, and UA cookie mismatch statistics.
  - Supports manual operator overrides (`LEGITIMATE`, `SUSPICIOUS`, or `RESET` to auto-verdict) with audit notes.
- **Forged Browser Build Detection (`BrowserVersionSyncService`):**
  - Detects both **impossible future major versions** (browser major versions exceeding the latest known release plus safety margin) and **forged build triples** (such as non-zero minor/build/patch segments in modern Chrome `101+` User-Agent strings where standard browsers always emit `.0.0.0`).
- **Interactive User-Agent Drilldown Modal:**
  - Provides a 24-hour hourly traffic chart, top originating ASNs and subnets, detailed heuristic indicator breakdown, and direct 1-click dynamic UA mitigation controls.

---

### 🍪 Visitor Cookie Minimum Age Guardrail & UA Mismatch Rollups *(Valve & Collector)*
- **`visitorCookieMinAgeSeconds` (Valve, default: `10` seconds):**
  - First-contact visitor tokens (`counter == 1`) must now reach a minimum age of `visitorCookieMinAgeSeconds` before granting `isReturningVisitor = true` reputation.
  - Defeats high-speed automated scrapers that accept the `Set-Cookie` header on their first request and immediately launch hundreds of requests within the same second.
  - Refreshed cookies (`counter > 1`) or configurations with `visitorCookieMinAgeSeconds="0"` pass immediately.
- **Subnet Rollup & Carpet Radar UA Mismatch Integration (Flyway V34):**
  - User-Agent cookie mismatch counts (`ua_mismatch_requests`) are now aggregated into `client_subnet_rollups` and surfaced directly in the Carpet Attack Radar and Mitigation Cockpit.
- **Enhanced Status Dashboard Rendering (`AntiDoSStatusRenderer`):**
  - Displays visitor cookie configuration badges (including `min-age`, inheritance status, and `enforce` vs. `track-only` UA mode) in both overview and detail HTML views.

---

### ⚙️ Zero-Dependency Host, JVM & Tomcat System Metrics *(Valve & Collector)*
- **`AntiDoSSystemMetrics` (Valve):**
  - Collects host CPU load (`processCpuLoad`, `systemCpuLoad`, `systemLoadAverage`), JVM heap utilization (`heapUsedBytes`, `heapMaxBytes`, `heapUsedPercent`), Garbage Collection counters (`gcCollectionCount`, `gcCollectionTimeMs`), and Tomcat connector worker thread saturation (`tomcatBusyThreads`, `tomcatMaxThreads`) via standard JMX/MXBeans without external libraries.
  - Rendered as a compact **Host Telemetry** bar in the Valve's HTML status pages and embedded under the `"system"` key in JSON responses.
- **Collector Heartbeat & Poll Log Persistence (Flyway V37):**
  - The Collector records host telemetry on every poll cycle in `endpoint_heartbeats` and `poll_event_log`, displaying live CPU, Heap, GC, and Tomcat thread utilization badges on the Fleet Overview and Server Details pages.

---

### ⚡ Dashboard Performance, Lazy Loading & UX Polish *(Collector)*
- **Tab-Based Lazy Loading & Index Optimization (`AnalyticsService`, Flyway V39):**
  - Analytics controllers now execute only the database queries required for the currently active tab (`traffic`, `user-agents`, or `endpoints`), backed by a new composite rollup index (`idx_rollups_bucket_server_valve`).
- **Clearer Event Status Terminology:**
  - Unblocked high-activity counter snapshots are now consistently labeled as `ALLOWED` (Unblocked) across the Events dashboard, filters, and server detail views.
- **HTMX In-Flight Loading Indicators:**
  - Expanded visual loading states across interactive buttons, filter forms, and navigation links.

---

## Migration & Upgrading

### Upgrading the Valve
Upgrading from Version 2.0.0 is fully backwards-compatible:
1. Replace `anti-dos-valve-2.0.0.jar` with `anti-dos-valve-2.1.0.jar` in `$CATALINA_BASE/lib/` (or `anti-dos-valve-2.1.0-tomcat9.jar` for Tomcat 9).
2. Existing `server.xml` configurations work without modification.
3. *Optional new parameters:*
   - `visitorCookieMinAgeSeconds="10"` (enabled by default at `10` seconds when `visitorCookieEnabled="true"`).
   - `mitigationBypassPrivateIPs="true"` (enabled by default).
   - `mitigationBypassIPs="<regex>"` to exempt trusted public gateways from dynamic CIDR/UA blocks.

### Upgrading the Collector
1. Replace `anti-dos-collector-2.0.0.jar` with `anti-dos-collector-2.1.0.jar`.
2. Flyway database schema migrations (**V34 through V41**) execute automatically on startup for both SQLite and PostgreSQL:
   - `V34__add_ua_mismatch_to_subnet_rollups.sql`
   - `V35__create_user_agent_memory_and_rollups.sql`
   - `V36__add_sample_returning_visitor_to_client_events.sql`
   - `V37__add_system_metrics_to_heartbeats_and_poll_log.sql`
   - `V38__add_user_agent_mitigation_rules.sql`
   - `V39__add_rollup_bucket_server_valve_index.sql`
   - `V40__create_endpoint_rollups.sql`
   - `V41__add_mitigation_bypass_to_monitored_valves.sql`
