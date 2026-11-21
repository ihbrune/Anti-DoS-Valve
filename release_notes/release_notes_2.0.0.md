# Release Notes – Version 2.0.0

Version 2.0.0 marks a major milestone in the evolution of the Anti-DoS-Valve ecosystem: **the graduation of the Anti-DoS Collector from preview status to a production-tested enterprise security center**, accompanied by **advanced User-Agent integrity enforcement in the Valve**, comprehensive **Role-Based Access Control (RBAC)**, and **intelligent capacity management for autonomous fleet defense**.

With Version 2.0.0, the Collector supports flexible multi-topology operational modes (`FULL`, `HEADLESS`, `OPERATOR`, `VIEWER`), interactive web login protection with fine-grained API security, autonomous defense with carpet-bombing radar and priority-based capacity budgeting, and deep forensic correlation across Autonomous Systems and client fingerprints.

DISCLAIMER: The collector is the result of a complete AI-driven development. Its complex architecture and advanced features are already in use with in a medium sized production environment with very positive feedback. However, the collector is still in active development and new features are being added regularly. Bugs are likely and should be reported. Feedback is always welcome. 

---

## Highlights

### 🔐 Built-in Authentication, RBAC & Login Protection *(Collector)*
To safeguard sensitive telemetry, forensic incident logs, and dynamic mitigation controls, the Collector now features native multi-token Role-Based Access Control and an interactive web authentication cockpit:

- **Interactive Login Interface (`/login`):**
  - Modern, self-contained login portal matching the dark/light SOC design system.
  - Session authentication via secure HTTP cookies (`SameSite=Strict`, `HttpOnly`, `Path=/`).
  - Configurable session timeout with automatic renewal and graceful logout (`/logout`).
- **Granular Multi-Token Roles:**
  - `ADMIN`: Complete administrative control, including node management, database maintenance (`vacuum`), retention cleanup, manual sync dispatch, and autonomous engine configuration.
  - `OPERATOR`: Tailored for Security Operations Center (SOC) analysts. Enables incident investigation, manual and autonomous mitigation rule management, incident note authoring, and report regeneration, while restricting underlying system maintenance.
  - `VIEWER`: Read-only access for executives, auditors, or NOC wallboard monitors. All state-mutating actions and API endpoints are blocked (`HTTP 403 Forbidden`).
- **Guarded Operational & AI APIs (`/api/v1/operational/*`):**
  - Dedicated REST endpoints designed for automation scripts, CI/CD pipelines, and AI coding agents.
  - Authenticated via standard `Authorization: Bearer <token>` headers or secure query tokens.
  - Provides programmatic access to fleet health, active mitigations, audit logs, and forensics.
- **Built-in Self-Protection & Rate Limiting:**
  - In-memory rate limiting shields the login endpoint and operational APIs against brute-force attacks and credential stuffing without external dependencies or Redis.
  - Client IP tracking with automatic temporary lockouts for abusive authentication attempts.
- **CLI Token Generation Utility:**
  - Administrators can generate cryptographically secure hex tokens directly via the CLI:
    ```bash
    java -jar anti-dos-collector-2.0.0.jar generate-token --name "soc-team" --role OPERATOR
    ```
- **Live User Identity & Role Banner (`viewer-banner.html`):**
  - Displays authenticated user badges, current operational roles, and quick logout links directly in the top navigation bar.

---

### 🌐 Flexible Operational Modes & Enterprise Topologies *(Collector)*
The Collector can now be deployed in four specialized operational modes to accommodate zero-trust network segregation:

1. **`FULL` Mode (Default All-in-One):**
   - Combines background polling, autonomous defense, database maintenance, and the web cockpit in a single process.
2. **`HEADLESS` Mode (Isolated Polling Worker):**
   - Designed to run as a backend systemd daemon in secure management subnets.
   - Carries sensitive Valve API credentials and network routes to Tomcat instances, but **binds to no HTTP port**, presenting zero external attack surface.
3. **`OPERATOR` Mode (SOC Analyst Web Cockpit):**
   - Runs the web interface on an internal network port.
   - Connects directly to the shared database (SQLite WAL or PostgreSQL) without needing network access to monitored Tomcat instances or holding Valve secrets.
   - Analysts manage rules in the database; the co-located `HEADLESS` worker synchronizes them asynchronously to the fleet.
4. **`VIEWER` Mode (Air-Gapped Forensics & Wallboards):**
   - Mounts live databases or copied snapshots in strict read-only mode (`PRAGMA query_only=ON`).
   - Perfect for offline post-mortem investigations on an analyst laptop without risking accidental database modifications.

---

### 🤖 Autonomous Defense & Carpet Radar Enhancements *(Collector)*
The autonomous mitigation engine has been substantially upgraded with smarter capacity budgeting, eviction heuristics, and performance caching:

- **Minimum Requests per Subnet (`carpetMinRequestsPerSubnet`, default `20`):**
  - Subnets are only auto-blocked if they generated at least `N` requests during the lookback window.
  - Shields rule capacity from low-density residential proxy scraper swarms that rotate across thousands of subnets with only 1–2 requests, focusing defense on high-impact attackers.
- **Priority-Based Capacity Allocation & Dynamic Eviction:**
  - When nearing configured capacity limits (`maxActiveRules`), subnets with the highest own request volume are prioritized for available slots.
  - **Releasing Inactive Rules Under Pressure (`AUTO_RELEASE_UNUSED`):** Automatically evicts older autonomous rules that blocked zero requests during their initial 10-minute observation window to free capacity for active high-volume attackers. Rules that actively blocked traffic or were created by human operators are never evicted early.
- **Coalesced Fleet Synchronization & Compact Labels:**
  - All block additions, releases, and TTL extensions in an evaluation cycle are synchronized to Tomcat Valves in a single batched atomic `replace` payload.
  - Valves receive compact labels (e.g. `AUTO_CARPET AS7922`) instead of verbose reason strings, keeping both synchronization payloads and `/antidos-status` JSON responses lean.
- **Radar In-Memory Caching & Performance Indexes (Flyway V33):**
  - In-memory calculation caching for Carpet Attack Radar metrics prevents repeated heavy database aggregations.
  - New database indexes on `mitigation_rules` and subnet rollups accelerate scheduled evaluation cycles.

---

### 🕵️ User-Agent Forensics, Bot Profiling & Browser Lag Engine *(Collector)*
Expanding upon initial bot categorizations, Version 2.0.0 introduces a deterministic multi-signal heuristic evaluation engine for client User-Agents:

- **12+ Client Family Classifications:**
  - Differentiates standard browsers, automated libraries (`Python-requests`, `curl`, `Scrapy`, `Go-http`, `Node-Fetch`), search crawlers (`Googlebot`, `Bingbot`), and AI scrapers (`LinkupBot`, `OpenAI`, `Anthropic`, `Perplexity`).
- **Authoritative Browser Release Version Sync & Lag Assessment:**
  - Automatically assesses major browser versions (Chrome, Firefox, Safari, Edge) against release timelines.
  - Flags outdated, unmaintained, or spoofed legacy browser headers frequently weaponized by residential proxy scraper networks.
- **Multi-Signal Heuristic Suspicion Scoring:**
  - Cross-references request incident rates (HTTP 429 rate blocks), Autonomous System types (hosting/datacenter vs. residential), and verified crawler identities to calculate objective risk badges: 🔴 `SUSPICIOUS`, 🟢 `LEGITIMATE`, and ⚪ `NEUTRAL`.
- **Authenticated Session Correlation:**
  - Tracks the proportion of requests carrying verified authentication cookies (`sampleAuthenticated`), distinguishing legitimate logged-in users from automated credential-less scrapers.

---

### 🍪 User-Agent Fingerprint Enforcement for Visitor Cookies *(Valve)*
Version 2.0.0 hardens the Valve's visitor tracking capabilities against token theft and cross-client cookie replay:

- **`enforceVisitorCookieUserAgent` (Valve):**
  - When enabled, cryptographic visitor tokens embed a secure SHA-256 fingerprint of the client's original User-Agent string.
  - If a visitor token is intercepted and replayed with a mismatched User-Agent, the Valve immediately detects the discrepancy, treats the client as unverified, and records telemetry.
- **Mismatch Telemetry & Forensics:**
  - Mismatch events are logged to `AntiDoSStatusRenderer` and captured by the Collector in `client_events` (via Flyway migration V32), alerting operators to active session hijacking or cookie spoofing attempts.

---

### 🛡️ Valve Reliability, Security & Infrastructure Hardening *(Valve)*
- **`alwaysAllowPrivateIPs` (Valve):**
  - Automatically exempts all private IPv4 and IPv6 ranges (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback `127.0.0.0/8` and `::1`, link-local `169.254.0.0/16` and `fe80::/10`, IPv6 ULA `fc00::/7`) without requiring complex regexes.
- **Noise Reduction in Status Top Counters:**
  - `AntiDoSStatusRenderer` now suppresses low-count noise below `activeMinCount` when extracting top active entries (`effActiveLimit > 0`), ensuring clean status displays and minimal memory consumption.
- **`statusConcurrencyTimeoutMs` (Valve):**
  - Protects Tomcat request threads and CPU capacity by strictly bounding concurrent status dashboard requests (`HTTP 503` fail-fast when overloaded).
- **Dual Servlet Compatibility:**
  - Full native support for Tomcat 10+ (`jakarta.servlet.*`) and shaded compatibility for Tomcat 9 (`javax.servlet.*`).

---

### 📊 Advanced Reporting, Advisor Diagnostics & Retention *(Collector)*
- **Verified Search & AI Crawler Telemetry in Daily Reports:**
  - Daily reports now provide a dedicated breakdown for verified search engines (`Googlebot`, `Bingbot`, etc.) and commercial AI crawlers (`AI_CRAWLER`), tracking total crawler volume, percentage of overall traffic, and unique IP cardinality.
- **Advisor Diagnostics for Undersized Slot Buffers (`SLOT_BUFFER_TUNING`):**
  - The Configuration Advisor proactively identifies Tomcat Valves configured with `numberOfSlots < 3`.
  - Explains that shallow ring buffers overwrite finalized slots before the Collector can poll `slot=previous`, and provides ready-to-paste `server.xml` XML recommendations (`numberOfSlots="10"`).
- **Clustered Outage & Incident Tracking:**
  - Daily reports automatically aggregate correlated rate-limiting spikes across multiple monitored nodes into unified incident clusters.
- **Internal vs. External Threat Segregation:**
  - Segregates anomalies originating from private subnets vs. public Internet transit in daily reports and the dashboard guide.
- **Automated Retention Cleanup for Stale Subnet Profiles & Mitigation Rules:**
  - The retention scheduler now routinely purges stale `subnet_profiles`, expired dynamic mitigation rules, and old audit trail entries, ensuring optimal database performance over time.
- **High-Density Table Navigation:**
  - Enhanced table layouts with sticky headers and responsive scrolling across audit trails, offenders, and crawler catalogs.

---

## Migration & Upgrading

### Upgrading the Valve
The Valve upgrade from 1.9.0 is fully backwards-compatible:
1. Replace `anti-dos-valve-1.9.0.jar` with `anti-dos-valve-2.0.0.jar` in `$CATALINA_BASE/lib/` (or `anti-dos-valve-2.0.0-tomcat9.jar` for Tomcat 9).
2. Existing configurations continue to function without changes.
3. To enable User-Agent fingerprint enforcement on visitor cookies, configure `enforceVisitorCookieUserAgent="true"` on the `<Valve>` in `server.xml`.

### Upgrading the Collector
1. Replace `anti-dos-collector-1.9.0.jar` with `anti-dos-collector-2.0.0.jar`.
2. Database schema migrations (V31 through V33) execute automatically on startup for SQLite and PostgreSQL:
   - `V31__add_always_allow_private_ips_to_monitored_valves.sql`
   - `V32__add_ua_mismatch_to_client_events.sql`
   - `V33__add_mitigation_and_rollup_performance_indexes.sql`
3. If upgrading an existing installation to use authentication, configure security tokens and operational modes in `collector-config.yaml` or via command-line arguments as detailed in [`collector/SETUP_GUIDE.md`](../collector/SETUP_GUIDE.md).
