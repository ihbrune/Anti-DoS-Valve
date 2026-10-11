# Anti-DoS-Valve: Agent & Developer Guide

This document serves as an onboarding and development guide for human developers and agentic AI coding assistants (e.g., Antigravity, OpenCode, Codex, Claude Code).

---

## 1. Project Overview & Architecture

**Anti-DoS-Valve** is a high-performance Apache Tomcat Valve designed to protect web applications against Denial-of-Service (DoS) attacks and abusive request rates (rate-limiting).

### Core Architectural Components:
* **`AntiDoSValve`:** The central Catalina valve (`ValveBase`). Intercepts incoming HTTP requests in Tomcat's request processing pipeline, extracts client IP addresses (handling proxies / headers), checks thresholds, and either forwards or blocks requests (HTTP 429).
* **`AntiDoSMonitor`:** Manages the sliding time window of request slots and runs a dedicated background thread for automated counter maintenance and eviction of expired IP entries.
* **`AntiDoSSlot` & `AntiDoSCounter`:** High-concurrency data structures counting requests per IP or subnet partition.
* **`AntiDoSStatusRenderer`:** Generates the internal HTML monitoring dashboard (`/antidos-status`), secured via IP filtering and path rules.
* **`AntiDoSLogThrottler`:** Prevents log-flooding during severe DoS incidents by rate-limiting log emission.

---

## 2. Core Development Constraints

1. **Zero Runtime Dependencies:**
   * **No** additional runtime libraries may be introduced in `pom.xml`.
   * The only compile/provided dependency is `org.apache.tomcat:tomcat-catalina` (`provided`).
2. **Tomcat 10 (Jakarta) & Tomcat 9 (Javax) Dual Compatibility:**
   * Source code is written against `jakarta.servlet.*` (Tomcat 10+).
   * Maven Shade Plugin produces a shaded secondary artifact (`*-tomcat9.jar`) during `package` by relocating `jakarta.servlet` packages to `javax.servlet`.
3. **Thread-Safety & Concurrency:**
   * The valve executes directly within the high-throughput request processing path of Tomcat.
   * Never use coarse-grained locks (`synchronized`) inside the request processing pipeline (`invoke()`).
   * Rely strictly on concurrency primitives such as `ConcurrentHashMap`, `LongAdder`, and atomic operations.

---

## 3. Build & Test Commands

| Command | Purpose |
|---|---|
| `mvn test` | Runs all fast unit and concurrency tests (~1-2 seconds). |
| `mvn test -Dtest=AntiDoSConcurrencyTest` | Runs dedicated concurrency and race-condition tests. |
| `mvn package` | Compiles and packages both the standard Valve JAR and the tomcat9-shaded JAR in `target/`. |
| `mvn verify` | Runs unit tests, packaging, and the full Docker integration test (`AntiDoSValveDockerIT`). |

---

## 4. End-to-End Tests & Docker

* **Testcontainers Integration Test (`AntiDoSValveDockerIT`):**
  * Automatically boots a real Tomcat container (`tomcat:10.1`), mounts the newly packaged Valve JAR and `docker/server.xml`.
  * Validates blocking behavior (HTTP 429), `nonRelevantPaths` exclusions, marking mode, and security restrictions using native Java 21 `HttpClient`.
  * Automatically executed during `mvn verify` (gracefully skipped if the Docker daemon is unreachable).
* **Manual Docker Demo:**
  * Refer to [docker/README.md](docker/README.md) and [docker/server.xml](docker/server.xml).

---

## 5. Checklist for New Configuration Parameters

Whenever a new configuration parameter is added to the Valve, the following areas must be kept in sync:
1. **Getters & Setters** in [AntiDoSValve.java](valve/src/main/java/org/henbru/antidos/AntiDoSValve.java).
2. **Defaults & Init Logic** in `initInternal()` / `reloadMonitor()`.
3. **Status Dashboard:** Display in [AntiDoSStatusRenderer.java](valve/src/main/java/org/henbru/antidos/AntiDoSStatusRenderer.java).
4. **HTML Configurator:** Form field in [anti-dos-valve-config-helper.html](anti-dos-valve-config-helper.html).
5. **Documentation:** Parameter reference table in [README.md](README.md) and demo configuration in [docker/server.xml](docker/server.xml).
6. **Unit Tests:** Parameter binding and behavioral tests in [AntiDoSValveTest.java](valve/src/test/java/org/henbru/antidos/AntiDoSValveTest.java).
