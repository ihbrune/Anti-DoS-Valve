# Anti-DoS-Valve: Agent & Developer Guide

This document serves as an onboarding and development guide for human developers and agentic AI coding assistants (e.g., Antigravity, OpenCode, Codex, Claude Code).

---

## 1. Project Overview & Multi-Module Architecture

**Anti-DoS-Valve Project** is a Maven multi-module project consisting of:
1. **`valve/` (`anti-dos-valve`):** High-performance Apache Tomcat Valve protecting web applications against Denial-of-Service (DoS) and abusive request rates.
2. **`collector/` (`anti-dos-collector`):** Standalone Spring Boot 3 & HTMX monitoring aggregator and analytics service collecting status from multiple Valve instances.
3. **`benchmark/` (`anti-dos-benchmark`):** Standalone JMH performance harness and deterministic traffic load simulator evaluating Valve monitor concurrency.
4. **`docker/`:** Standalone demo Tomcat environment and integration test assets.

### Core Architectural Components in `valve/`:
* **`AntiDoSValve`:** The central Catalina valve (`ValveBase`). Intercepts incoming HTTP requests in Tomcat's request processing pipeline, extracts client IP addresses (handling proxies / headers), checks thresholds, and either forwards or blocks requests (HTTP 429).
* **`AntiDoSMonitor`:** Manages the sliding time window of request slots and runs a dedicated background thread for automated counter maintenance and eviction of expired IP entries.
* **`AntiDoSSlot` & `AntiDoSCounter`:** High-concurrency data structures counting requests per IP or subnet partition.
* **`AntiDoSStatusRenderer`:** Generates the internal HTML monitoring dashboard (`/antidos-status`), secured via IP filtering and path rules.
* **`AntiDoSLogThrottler`:** Prevents log-flooding during severe DoS incidents by rate-limiting log emission.

### Core Architectural Components in `collector/` & `benchmark/`:
* For dedicated Collector guidelines, data models, and commands, refer to [collector/AGENTS.md](collector/AGENTS.md) and [collector/README.md](collector/README.md).
* For dedicated Benchmark guidelines, traffic profiles, and history tracking, refer to [benchmark/AGENTS.md](benchmark/AGENTS.md) and [benchmark/README.md](benchmark/README.md).

---

## 2. Core Development Constraints

### Constraints for `valve/` (Strict Minimal Runtime):
1. **Zero Runtime Dependencies:**
   * **No** additional runtime libraries may be introduced in `valve/pom.xml`.
   * The only compile/provided dependency is `org.apache.tomcat:tomcat-catalina` (`provided`).
2. **Tomcat 10 (Jakarta) & Tomcat 9 (Javax) Dual Compatibility:**
   * Source code is written against `jakarta.servlet.*` (Tomcat 10+).
   * Maven Shade Plugin produces a shaded secondary artifact (`*-tomcat9.jar`) during `package` by relocating `jakarta.servlet` packages to `javax.servlet`.
3. **Thread-Safety & Concurrency:**
   * Executes directly within the high-throughput request processing path of Tomcat.
   * Never use coarse-grained locks (`synchronized`) inside the request processing pipeline (`invoke()`).
   * Rely strictly on concurrency primitives such as `ConcurrentHashMap`, `LongAdder`, and atomic operations.
4. **Self-Contained Dashboard Styling & CSP:**
   * All HTML/CSS/JS in `AntiDoSStatusRenderer` must remain 100% self-contained string templates without external assets.
   * Maintain both Dark and Light mode palettes in `appendCommonHeadStyles()`.
   * The Content-Security-Policy header on HTML responses must permit `script-src 'unsafe-inline'` for the theme toggle button and anti-FOUC initialization.

### Constraints for `collector/` (Modern Spring Boot Ecosystem):
1. **Java 21 & Virtual Threads:**
   * Runs as an independent service with `spring.threads.virtual.enabled=true`.
2. **Database Support:**
   * SQLite (default zero-ops file db) and PostgreSQL (production multi-server).
   * All schema migrations managed via versioned Flyway SQL scripts.
3. **No Heavy Frontend Frameworks:**
   * Uses server-side Thymeleaf templates with HTMX for real-time reactivity without Node.js/npm dependencies.

---

## 3. Build & Test Commands

| Command | Purpose |
|---|---|
| `mvn test` | Runs all unit and concurrency tests across all modules. |
| `mvn test -pl valve` | Runs only valve unit & concurrency tests (~1-2 seconds). |
| `mvn test -pl collector` | Runs only collector unit & integration tests. |
| `mvn test -pl benchmark` | Runs benchmark unit tests (TrafficSimulator verification). |
| `mvn package` | Compiles and packages `valve` (including tomcat9 jar), `collector` executable JAR, and `benchmark` uberjar. |
| `mvn package -pl benchmark -DskipTests` | Packages standalone JMH uberjar (`benchmark/target/benchmarks.jar`). |
| `mvn verify` | Runs all tests, packaging, and Docker integration tests (`AntiDoSValveDockerIT`). |
| `java -cp benchmark/target/benchmarks.jar org.henbru.antidos.benchmark.BenchmarkRunner` | Runs baseline + monitor benchmarks and appends normalized scores to `.benchmarks/history.jsonl`. |

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
