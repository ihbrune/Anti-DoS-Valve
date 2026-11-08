# Release Notes – Version 1.8.0

Version 1.8.0 is the largest release since the project started. It extends the **Anti-DoS Valve** with first-party visitor and authentication tracking, request forensics, honeypot semantics and an OpenAPI-documented status API — and it introduces the **Anti-DoS Collector**, a new fleet monitoring and forensics service that aggregates telemetry from many Valve instances.

> [!IMPORTANT]
> **The Collector is a preview component and is not final.** It is functional, covered by an extensive test suite and used for day-to-day forensics, but its database schema, REST API, configuration keys and UI may still change between minor releases, and it has no built-in authentication (see [Collector status](#-anti-dos-collector--preview-status)). **The Valve itself is stable** and remains fully usable without the Collector. For production deployments of the Valve alone, the compatibility statement in [Upgrading](#upgrading) applies.

---

## Highlights

### 🆕 Anti-DoS Collector (Preview)
A standalone Spring Boot 3 / Java 21 service with a server-rendered HTMX dashboard that polls the status endpoints of any number of Valves and turns their short-lived in-memory telemetry into persistent, searchable forensics. See [`collector/README.md`](../collector/README.md), [`collector/SETUP_GUIDE.md`](../collector/SETUP_GUIDE.md) and [`collector/DASHBOARD_GUIDE.md`](../collector/DASHBOARD_GUIDE.md).

- **Fleet overview & server detail views:** KPI cards, per-node valve configuration discovery, slot history timeline and node-specific incident lists.
- **Incident Explorer:** multi-dimensional filtering (server, valve, client, ASN, client type, status), server-side pagination, inline notes.
- **Top Offender Analytics:** ranking by blocked or total requests, aggregation by client, subnet or ASN, rotating proxy cluster detection.
- **Visual Analytics:** traffic/attack timeline, traffic composition (bot mix), residential proxy & subnet scatterplot with ASN rollup and authentication/returning-visitor filters.
- **Subnet Profiles & Baseline Radar:** 30-day baselines with dynamic 3-phase calibration, dormancy breakout, surge and new-subnet detection.
- **Config & False-Positive Advisor:** rule-based findings (search-engine collateral, internal infrastructure blocked, residential/NAT false-positive risk, cloud offloading, stealth carpet scrapers, chameleon bots, sampling recommendations) with copy-ready `server.xml` snippets, also available via REST.
- **IP intelligence & enrichment:** offline MaxMind/DB-IP (`.mmdb`) ASN and country lookup, client classification (datacenter, residential, Tor exit node, privacy relay, search engine, AI crawler, private network), verified crawler feeds (Googlebot, Bingbot, Applebot, OpenAI, …) and an automated MMDB update script.
- **Network Notes & Investigation History:** persistent operator verdicts per IP, subnet or ASN with JSON export/import, retention immunity, and a local browser-side investigation history drawer.
- **Operational Day Reports:** permanent daily summaries (hourly traffic breakdown, ASN volume, blocked-slot ratios, operator notes) that are protected from accidental overwrite once raw telemetry has been pruned.
- **Retention & maintenance:** differential retention for active vs. incident events, tiered rollup compaction, daily/hourly cleanup, SQLite `VACUUM` and one-click maintenance actions on the System page.
- **Interactive Demo Mode:** `java -jar anti-dos-collector-1.8.0.jar demo [n]` boots a simulated fleet with seven days of realistic attack waves in an isolated database.
- **Built-in documentation and APIs:** in-app markdown help center, `DB_FORENSICS_GUIDE.md` SQL runbook, JSON APIs under `/api/v1/…` including blocked-IP export (`json` or plain text for firewall ingest).
- **Storage:** SQLite (WAL, zero-ops default) or PostgreSQL, all schema changes managed by versioned Flyway migrations.
- **UI:** English-only, light/dark theme, no Node.js/npm toolchain (Thymeleaf, vendored HTMX and Chart.js with license files).

### 🍪 Visitor Cookies — Proof-of-Prior-Visit *(Valve)*
New opt-in first-party visitor tracking (`visitorCookieEnabled`, default `false`):
- **AES-256-GCM (AEAD)** tokens (~58 characters) bound to the client's masked subnet, with expiry and a saturating visit counter; forged or altered cookies are rejected before parsing. Zero runtime dependencies.
- Parameters: `visitorCookieName`, `visitorCookieSecret` (shared key for stateless multi-node validation), `visitorCookieTtlSeconds`, `visitorCookieRefreshRatio`, `visitorCookieSubnetMaskV4/V6`, `visitorCookiePath`, `visitorCookieDomain`, `visitorCookieSameSite`, `visitorCookieSecure`.
- **Multi-valve inheritance:** the upstream valve publishes an immutable `AntiDoSVisitorContext` (plus `org.henbru.antidos.RETURNING_VISITOR`, `FIRST_CONTACT`, `VISITOR_COUNTER` request attributes); downstream valves inherit it without any configuration.
- The Collector displays returning-visitor ratios and uses them in its false-positive advisor.

### 🔐 Authentication Session Tracking & Tiered Rate Limiting *(Valve)*
- **`authTrackingMode="COOKIE"`** passively observes login responses (`authLoginPaths`, `authCookieName`) and recognises authenticated follow-up requests without understanding application-specific session formats. Supports `authSessionTtlSeconds` and `maxAuthCacheSize`; honours `Max-Age` and logout invalidation.
- **Allocation-free hot path:** a JVM-wide `AntiDoSAuthSessionCache` uses a per-JVM salted 64-bit hash and a lock-free primitive open-addressing table (16 bytes per session, ~800 KB for the default 50,000 sessions).
- **`relevantAuthScope`** (`ALL`, `AUTHENTICATED_ONLY`, `UNAUTHENTICATED_ONLY`) lets cascaded valves enforce separate budgets for anonymous and authenticated traffic.
- Status dashboard and Collector show authenticated request counts only when tracking is active.

### 🔍 Request Forensics *(Valve)*
- **Request sample snapshots:** the first blocked or marked request of a counter captures method, URI and User-Agent (`🔍 METHOD /path` in the Collector with 1-click note triage).
- **`activeSampleThreshold`** (default `0` = off): captures a sample for *allowed* clients or subnets that exceed a per-slot threshold — ideal for diagnosing distributed stealth scrapers that stay below the blocking limit.
- **Distinct client and user-agent cardinality:** a lock-free 256-bit subnet bitmask tracks distinct client IPs per aggregated subnet; distinct user agents are tracked as well.
- **`trackAlwaysForbiddenInMonitor`** (default `false`): optionally registers `alwaysForbiddenIPs` hits in the monitor with zero tolerance so individual offenders appear in the status dashboard and Collector.

### 🍯 Honeypot & Marking Semantics *(Valve)*
- **Zero-tolerance mode:** `allowedRequestsPerSlot="0"` blocks (or marks) the very first request — a true honeypot trap, combinable with `serverWideBlocking`.
- **Blocked vs. marked** are now tracked and reported as distinct states throughout slots, rollups, reports and the Collector UI.
- Marking-mode valves are fully supported by the Collector.

### 📡 Status Endpoint & API *(Valve)*
- **OpenAPI 3.1 specification** served at `?format=openapi` and as an interactive documentation view (`?view=docs`); static copies in [`docs/openapi.yaml`](../docs/openapi.yaml) and [`docs/openapi.json`](../docs/openapi.json).
- **Delta-based filtering** (`sinceBlockedOrder`, `sinceActiveOrder`) and granular blocked/active client limits for efficient incremental polling.
- **Collector lease:** with `collectorIntegration="auto"` (default) extended telemetry is activated for a rolling two-minute lease only when a collector polls `?format=json`; otherwise it stays dormant with zero overhead. Only JSON status requests touch the lease.
- New `description` attribute, theme-aware (dark/light) status dashboard, and CSP updated to permit the inline theme toggle.

### 🧱 Project Structure
- The repository is now a **Maven multi-module build**: `valve/` (`anti-dos-valve`, zero runtime dependencies), `collector/`, `benchmark/` (JMH harness and traffic simulator) and `docker/`.
- The Tomcat 9 (`javax.servlet`) build continues to be produced as `anti-dos-valve-1.8.0-tomcat9.jar`.
- **Action required for custom build setups:** since the valve moved into the `valve/` submodule, scripts and CI jobs that build only the valve must use `mvn package -pl valve` and read the JARs from `valve/target/` instead of `target/`. See the *Project Structure* section in the [README](../README.md).

---

## 🧪 Anti-DoS Collector — Preview Status

The Collector is deliberately released as a **preview**. What this means in practice:

| Area | Status |
| :--- | :--- |
| Ingestion, storage, dashboards, reports, advisor | Implemented and tested; feature-complete enough for forensic work. |
| Database schema | Managed by Flyway (V1–V24). Migrations run automatically, but schema changes may still occur — **back up your database before upgrading**. |
| REST API (`/api/v1/…`) and configuration keys | May change in minor releases. |
| Authentication / authorization of the dashboard | **Not included.** Bind to an internal interface or place it behind a reverse proxy with authentication. |
| Closed-loop defense (blocklist push to Valves, adaptive fleet thresholds, WAF export) | **Not implemented** — roadmap items described in `collector/README.md`. |
| Scale | Verified for small and medium fleets with several million requests per day; no formal capacity guidance yet. |

Feedback and bug reports on the Collector are especially welcome.

---

## Upgrading

### Valve
Upgrading the Valve from 1.7.0 is intended to be backwards-compatible:
1. Replace `anti-dos-valve-1.7.0.jar` with `anti-dos-valve-1.8.0.jar` (or `anti-dos-valve-1.8.0-tomcat9.jar` for Tomcat 9).
2. Existing configurations continue to work without modification; all new attributes are optional and default to disabled (`visitorCookieEnabled="false"`, `authTrackingMode="OFF"`, `activeSampleThreshold="0"`, `trackAlwaysForbiddenInMonitor="false"`, `relevantAuthScope="ALL"`).
3. The JSON status payload gained additional fields; consumers that parse it strictly should tolerate unknown properties.

### Collector
There is no upgrade path from an earlier release, as this is its first release. To try it:
```bash
mvn package -pl collector -DskipTests
java -jar collector/target/anti-dos-collector-1.8.0.jar demo
```
For production setup see [`collector/SETUP_GUIDE.md`](../collector/SETUP_GUIDE.md).
