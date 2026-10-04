# Release Notes – Version 1.6.0

Version 1.6.0 is a major feature release introducing a lightweight, built-in **HTTP Status Dashboard** for real-time monitoring and container observability, official **Tomcat 9 compatibility** via automated bytecode relocation, enhanced XML configuration handling, and persistence upgrades to the interactive configuration helper.

---

## Highlights

### ⚡ Built-in HTTP Status Dashboard & Observability Endpoint
In modern containerized and cloud environments (Docker, Kubernetes), traditional JMX ports are often inaccessible or require cumbersome port-forwarding and certificate management. Version 1.6.0 introduces an optional, built-in **HTTP Status Dashboard** to monitor the valve directly over HTTP/HTTPS:

- **Single Pane of Glass (Multi-Valve Aggregation):** When configuring `statusUri` on any valve, it automatically discovers and aggregates metrics from all active Anti-DoS valves in the same Tomcat JVM.
- **Real-Time Fleet & Health Overview:** Displays active operating modes (`BLOCKING` / `MARKING`), HTTP status codes, slot parameters, subnet masks, cache capacity vs. low/high watermarks, and lifetime request and block counters.
- **Interactive Details Drill-down (`?action=details&target=<monitorName>`):**
  - **Top Active Clients:** Inspect top IP/subnet counters with per-slot request histories.
  - **Blocked Clients:** Live list of currently blocked IPs/subnets with exact remaining lock time (seconds countdown) and total request counts.
  - **Safety Indicators:** Real-time visibility into cache fill rates, eviction states, and circuit breaker status.
- **REST / JSON API (`?format=json` or `Accept: application/json`):** Full machine-readable JSON status endpoint for automated health checks, Prometheus scrapers, Datadog, Zabbix, or custom dashboards.
- **Dedicated Status Valve Support:** Configure a valve purely as an administrative status dashboard without attaching rate-limiting overhead to that valve instance.
- **Multi-Layer Defense & Security Architecture:**
  - **Secure by Default:** Completely disabled unless `statusUri` is explicitly configured.
  - **Cryptographic Startup Token:** Generates a secure, console-friendly 16–20 character lowercase HEX token on startup if no custom password is set.
  - **Asymmetric Rate Limiting:** Status authentication attempts are monitored by the valve itself. Failed attempts trigger rate limiting, and brute-force guessing automatically results in an IP ban (`HTTP 429`).
  - **IP Whitelisting (`statusAllowedIPs`):** Restrict access via regex (e.g. `127\.0\.0\.1|::1|10\..*`). Unauthorized clients receive `404 Not Found` to conceal endpoint existence.
  - **Constant-Time Verification:** Uses `MessageDigest.isEqual(...)` to eliminate timing side-channel attacks.
  - **Ultra-lightweight:** 100% self-contained HTML (< 4 KB), zero external assets, no template engine overhead.

---

## Compatibility & Deployment

### 🔄 Dual Distribution: Tomcat 9 & Tomcat 10/11 Support
- **Automated Shaded Build:** Added `maven-shade-plugin` relocation to automatically remap `jakarta.servlet.*` packages to legacy `javax.servlet.*`.
- **Dual Artifacts:** Every build now produces two drop-in JARs in `target/`:
  - `anti-dos-valve-1.6.0.jar` for **Tomcat 10 and 11** (Jakarta EE)
  - `anti-dos-valve-1.6.0-tomcat9.jar` for legacy **Tomcat 9** deployments (`javax.servlet`)
- Enables legacy Tomcat 9 infrastructure to leverage all modern features—including subnet aggregation, server-wide blocking, and the status dashboard—without code changes.

### ⚙️ Robust String-Based XML Configuration Setters
- Added overloaded `String`-accepting setters for all core configuration attributes (`maxIPCacheSize`, `slotLength`, `numberOfSlots`, `allowedRequestsPerSlot`, `shareOfRetainedFormerRequests`, `serverWideBlocking`, `simulationMode`, `maxBlockedIPCacheSize`, `httpStatusCode`).
- Eliminates potential type-coercion and reflection pitfalls during Tomcat Digester rule evaluation in `server.xml`.

---

## Interactive Configuration Helper & Simulator Upgrades

Enhancements to [`anti-dos-valve-config-helper.html`](https://github.com/ihbrune/Anti-DoS-Valve/blob/master/anti-dos-valve-config-helper.html):

- **Browser LocalStorage Persistence:** Form parameters, selected presets, compact XML toggles, and simulator configurations are now automatically persisted in `localStorage` across browser refreshes and restarts, with schema validation and one-click reset.
- **Dynamic Subnet Mask Validation & Capacity Hints:** Real-time validation for IPv4 and IPv6 subnet masks (both CIDR prefixes and dotted-decimal notation) with live calculation of address aggregation capacities (e.g. 256 addresses for `/24`, quintillions for `/64`).
- **Status Dashboard Configurator:** Added configuration controls and presets for `statusUri`, `statusAllowedIPs`, and `statusPassword` with instant XML generation.

---

## Architecture & Code Quality

- **Decoupled Architecture:** Extracted all dashboard HTML and JSON generation logic into a dedicated, thoroughly tested [AntiDoSStatusRenderer](file:///Users/hbrune/Antigravity/Anti-DoS-Valve/src/main/java/org/henbru/antidos/AntiDoSStatusRenderer.java).
- **Expanded Test Suite:** Added comprehensive unit tests covering the status dashboard, IP whitelisting regex matching, token authentication, and JSON API payloads (bringing the suite to 85 passing tests).
- **Code Cleanups:** Removed obsolete imports and streamlined asynchronous eviction test boundaries.

---

## Upgrading from Version 1.5.0

Upgrading to 1.6.0 is fully backwards-compatible:
1. Replace `anti-dos-valve-1.5.0.jar` with `anti-dos-valve-1.6.0.jar` (or `anti-dos-valve-1.6.0-tomcat9.jar` for Tomcat 9).
2. Existing configurations continue to work without changes.
3. To enable the status dashboard, add `statusUri="/antidos-status"` (and optionally `statusAllowedIPs`) to your valve configuration in `server.xml`.