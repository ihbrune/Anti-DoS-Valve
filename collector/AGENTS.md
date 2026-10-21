# Anti-DoS-Collector: Agent & Developer Guide

This document serves as the architectural reference and development guide for human developers and agentic AI coding assistants working on the **Anti-DoS-Collector** module.

---

## 1. Module Overview & Architecture

**Anti-DoS-Collector** is an automated aggregation, monitoring, and analytics service designed to poll, persist, and visualize security telemetry from a fleet of **Anti-DoS-Valve** instances across multiple servers.

### Core Architectural Layers:
* **`config/`:** Configuration management for endpoints, database connection, retention policies, and application settings.
* **`poller/`:** Scheduled polling engine utilizing Java 21 `HttpClient` and Virtual Threads. Handles endpoint polling, intermediate in-progress slot updates, and recovery of missed slots via `slotKey`.
* **`enrichment/`:** Asynchronous IP metadata enrichment engine. Includes `MmdbEnrichmentProvider` (DB-IP / MaxMind MMDB), `AsnClassifierService` (layered defaults + custom overlay), `CrawlerSyncService` (dynamic JSON feed synchronizer with orphan cleanup), and `BackgroundEnrichmentWorker`.
* **`storage/`:** Data access layer backed by Spring Data / `JdbcTemplate` with Flyway migrations supporting both **SQLite** (default zero-ops) and **PostgreSQL** (production fleet scale).
* **`web/`:** Web dashboard driven by Spring MVC, Thymeleaf, and **HTMX** for real-time reactivity without client-side JavaScript build tooling.
* **`cli/`:** Command-line utilities (e.g. `test-endpoint`, `add-endpoint`) for operators to verify connectivity and generate configuration blocks.
* **`demo/`:** Built-in exploration mode (`MockValveController`, `MockValveSimulator`, `DemoModeService`, `DemoDataSeeder`) simulating multi-node fleets and pre-populating 7 days of realistic attack and diurnal telemetry into an isolated database (`antidos-collector-demo.db`).

---

## 2. Core Constraints & Conventions

1. **Virtual Threads Enabled:**
   * All polling, enrichment workers, and web request execution run on Java 21 Virtual Threads (`spring.threads.virtual.enabled=true`).
2. **Flyway Migrations:**
   * Never modify an existing, committed Flyway migration script!
   * Always provide migrations for both dialects:
     * `src/main/resources/db/migration/sqlite/V<N>__<description>.sql`
     * `src/main/resources/db/migration/postgresql/V<N>__<description>.sql`
   * Schema tables must remain idempotent and compatible with batch upserts (`ON CONFLICT (...) DO UPDATE`).
3. **Frontend Aesthetics & Reactivity:**
   * Follow the rich aesthetics guidelines: modern dark/light mode palette, glassmorphism, responsive cards, crisp typography.
   * **CSS Custom Properties (Variables):** Never use hardcoded colors (e.g. `#0f172a`, `#fff`) in HTML/CSS templates or components. Rely strictly on CSS variables (`var(--bg-card)`, `var(--text-primary)`, etc.) to preserve seamless Dark/Light theme switching.
   * **Theme Switcher & Anti-FOUC:** All primary view templates must include `<script th:src="@{/js/theme.js}"></script>` in `<head>` (synchronous anti-FOUC) and provide the theme toggle button in the navbar (`.btn-theme-toggle`).
   * Use HTMX attributes (`hx-get`, `hx-post`, `hx-trigger`, `hx-swap`) for dynamic updates rather than heavy external JavaScript frameworks.
4. **IP Storage, Forensics & Enrichment Architecture:**
   * **Decoupled Ingestion:** Polling threads write events with `enrichment_status = 'PENDING'` immediately. `BackgroundEnrichmentWorker` resolves ASN, Geo, and Client Classification asynchronously to guarantee sub-millisecond polling cycles.
   * **IPv4 Range Storage:** Stored as 32-bit unsigned `BIGINT` (`ip_v4_start`, `ip_v4_end`).
   * **IPv6 Upper-64-Bit Prefix Storage:** Stored as 16-character lowercase hex strings (`ip_v6_start`, `ip_v6_end`). Intentionally limited to the upper 64-bit routing prefix because individual host bits (/65-/128) are ephemeral due to IPv6 Privacy Extensions (RFC 4941).
   * **Subnet & ASN Rollup:** Supports `/24` & `/64` Subnet Rollup and **ASN Rollup** (`groupBy=ASN`) to aggregate rotating residential proxy botnets across multiple networks.
   * **Search & Containment Queries:** Never use SQL `LIKE` for IP ranges! Always use the mathematical interval overlap condition (`ip_start <= :searchEnd AND ip_end >= :searchStart`) via `IpNetworkUtil.parseSearchQuery()`.
   * **Layered Configuration:** Default datacenter ASNs packaged in `classpath:asns/default-datacenter-asns.txt`. Operators customize via `custom-datacenter-asns.txt` (`+12345` to add, `-24940` to exclude) without Git checkout conflicts.
   * **Client Classifications:** Enriched into categories: `DATACENTER` (Cloud/VPS/Hoster), `RESIDENTIAL` (ISP/End-user), `SEARCH_ENGINE` (Verified Googlebot/Bingbot), `AI_CRAWLER` (Verified OpenAI/ChatGPT), `TOR_EXIT_NODE` (Official Tor bulk exit nodes), `MOBILE` (Cellular/CGNAT), and `PRIVATE_NETWORK` (RFC 1918, RFC 4193 ULA, loopback, link-local).
   * **Multi-Source Intelligence & Entity Normalization:** IP and subnet metadata is centralized in `network_entity`, referenced by events via `entity_id`. The high-throughput in-memory interval index (`IntelRegistry`) resolves multi-source classifications (`intel_source`, `intel_range`) with microsecond lookup performance.
   * **Crawler & Anonymizer Feed Management:** Verified search engine, AI crawler, and Tor exit node IP ranges periodically updated from remote feeds with automatic orphan cleanup upon configuration changes, manageable via `/crawlers`.
   * **View Separation:** The root dashboard (`/`) is an executive overview. Advanced filtering belongs in `/events` (Incident Explorer), `/offenders` (Top Offender Analytics), and `/crawlers` (Bot Feeds).

---

## 3. Build & Test Commands

| Command | Purpose |
|---|---|
| `mvn test -pl collector` | Runs all unit and database migration tests for the collector. |
| `mvn package -pl collector` | Builds the executable Spring Boot Fat-JAR in `collector/target/anti-dos-collector-1.7.2.jar`. |
| `mvn spring-boot:run -pl collector` | Starts the collector service locally. |
| `mvn spring-boot:run -pl collector -Dspring-boot.run.arguments="demo"` | Starts the collector in zero-configuration Demo Mode with isolated database. |
| `mvn spring-boot:run -pl collector -Dspring-boot.run.arguments="demo 4"` | Starts Demo Mode with fleet scaling (4 instances per type = 12 total servers A..D). |
