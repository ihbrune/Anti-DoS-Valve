# Anti-DoS-Collector: Agent & Developer Guide

This document serves as the architectural reference and development guide for human developers and agentic AI coding assistants working on the **Anti-DoS-Collector** module.

---

## 1. Module Overview & Architecture

**Anti-DoS-Collector** is an automated aggregation, monitoring, and analytics service designed to poll, persist, and visualize security telemetry from a fleet of **Anti-DoS-Valve** instances across multiple servers.

### Core Architectural Layers:
* **`config/`:** Configuration management for endpoints, database connection, retention policies, and application settings.
* **`poller/`:** Scheduled polling engine utilizing Java 21 `HttpClient` and Virtual Threads. Handles endpoint polling, intermediate in-progress slot updates, and recovery of missed slots via `slotKey`.
* **`storage/`:** Data access layer backed by Spring Data / `JdbcTemplate` with Flyway migrations supporting both **SQLite** (default zero-ops) and **PostgreSQL** (production fleet scale).
* **`web/`:** Web dashboard driven by Spring MVC, Thymeleaf, and **HTMX** for real-time reactivity without client-side JavaScript build tooling.
* **`cli/`:** Command-line utilities (e.g. `test-endpoint`, `add-endpoint`) for operators to verify connectivity and generate configuration blocks.
* **`demo/`:** Built-in exploration mode (`MockValveController`, `MockValveSimulator`, `DemoModeService`, `DemoDataSeeder`) simulating multi-node fleets and pre-populating 7 days of realistic attack and diurnal telemetry into an isolated database (`antidos-collector-demo.db`).

---

## 2. Core Constraints & Conventions

1. **Virtual Threads Enabled:**
   * All polling and web request execution run on Java 21 Virtual Threads (`spring.threads.virtual.enabled=true`).
2. **Flyway Migrations:**
   * Never modify an existing, committed Flyway migration script!
   * Always provide migrations for both dialects:
     * `src/main/resources/db/migration/sqlite/V<N>__<description>.sql`
     * `src/main/resources/db/migration/postgresql/V<N>__<description>.sql`
   * Schema tables must remain idempotent and compatible with batch upserts (`ON CONFLICT (...) DO UPDATE`).
3. **Frontend Aesthetics & Reactivity:**
   * Follow the rich aesthetics guidelines: modern dark/light mode palette, glassmorphism, responsive cards, crisp typography.
   * Use HTMX attributes (`hx-get`, `hx-trigger`, `hx-swap`) for dynamic updates rather than heavy external JavaScript frameworks.
4. **IP Storage & Subnet Forensics Architecture:**
   * **IPv4 Range Storage:** Stored as 32-bit unsigned `BIGINT` (`ip_v4_start`, `ip_v4_end`).
   * **IPv6 Upper-64-Bit Prefix Storage:** Stored as 16-character lowercase hex strings (`ip_v6_start`, `ip_v6_end`). Intentionally limited to the upper 64-bit routing prefix because individual host bits (/65-/128) are ephemeral due to IPv6 Privacy Extensions (RFC 4941).
   * **Canonical `subnet_group`:** Contains the canonical `/24` (IPv4) or `/64` (IPv6) representation for high-speed Subnet Rollup aggregation (correlating distributed residential proxy botnets).
   * **Search & Containment Queries:** Never use SQL `LIKE` for IP ranges! Always use the mathematical interval overlap condition (`ip_start <= :searchEnd AND ip_end >= :searchStart`) via `IpNetworkUtil.parseSearchQuery()`.
   * **View Separation:** The root dashboard (`/`) is an executive overview. Advanced filtering (multi-server, multi-valve, custom time windows, CIDR search) belongs in `/events` (Incident Explorer) and `/offenders` (Top Offender Analytics).

---

## 3. Build & Test Commands

| Command | Purpose |
|---|---|
| `mvn test -pl collector` | Runs all unit and database migration tests for the collector. |
| `mvn package -pl collector` | Builds the executable Spring Boot Fat-JAR in `collector/target/anti-dos-collector-1.7.0.jar`. |
| `mvn spring-boot:run -pl collector` | Starts the collector service locally. |
| `mvn spring-boot:run -pl collector -Dspring-boot.run.arguments="demo"` | Starts the collector in zero-configuration Demo Mode with isolated database. |
