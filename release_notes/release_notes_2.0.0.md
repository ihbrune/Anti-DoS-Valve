# Release Notes – Version 2.0.0

Version 2.0.0 marks a major milestone in the evolution of the Anti-DoS-Valve ecosystem: **the graduation of the Anti-DoS Collector from preview status to a matured, production-tested enterprise security center**, accompanied by **advanced User-Agent integrity enforcement in the Valve** and comprehensive **Role-Based Access Control (RBAC)**.

With Version 2.0.0, the Collector supports flexible multi-topology operational modes (`FULL`, `HEADLESS`, `OPERATOR`, `VIEWER`), interactive web login protection with fine-grained API security, autonomous defense with carpet-bombing radar, and deep forensic correlation across Autonomous Systems and client fingerprints.

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

### 🕵️ User-Agent Forensics, Bot Profiling & Browser Lag Engine *(Collector)*
Expanding upon initial bot categorizations, Version 2.0.0 introduces a deterministic multi-signal heuristic evaluation engine for client User-Agents:

- **12+ Client Family Classifications:**
  - Differentiates standard browsers, automated libraries (`Python-requests`, `curl`, `Scrapy`, `Go-http`, `Node-Fetch`), search crawlers (`Googlebot`, `Bingbot`), and AI scrapers (`LinkupBot`, `OpenAI`, `Anthropic`).
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
- **`statusConcurrencyTimeoutMs` (Valve):**
  - Protects Tomcat request threads and CPU capacity by strictly bounding concurrent status dashboard requests (`HTTP 503` fail-fast when overloaded).
- **Dual Servlet Compatibility:**
  - Full native support for Tomcat 10+ (`jakarta.servlet.*`) and shaded compatibility for Tomcat 9 (`javax.servlet.*`).

---

### 📊 Advanced Reporting & Forensic Analytics *(Collector)*
- **Clustered Outage & Incident Tracking:**
  - Daily reports automatically aggregate correlated rate-limiting spikes across multiple monitored nodes into unified incident clusters.
- **Internal vs. External Threat Segregation:**
  - Segregates anomalies originating from private subnets vs. public Internet transit in daily reports and the dashboard guide.
- **ASN & Subnet Deterrence Lifecycle:**
  - Complete tracking of active, persistent, and deterred attacker behavior across Autonomous Systems.
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
2. Database schema migrations (V31 through V32) execute automatically on startup for SQLite and PostgreSQL:
   - `V31__add_always_allow_private_ips_to_monitored_valves.sql`
   - `V32__add_ua_mismatch_to_client_events.sql`
3. If upgrading an existing installation to use authentication, configure security tokens and operational modes in `collector-config.yaml` or via command-line arguments as detailed in [`collector/SETUP_GUIDE.md`](../collector/SETUP_GUIDE.md).
