# Release Notes – Version 1.5.0

Version 1.5.0 is a substantial release that modernizes the entire codebase, significantly improves
reliability under concurrent load, and introduces several new features aimed at defending against
today's most challenging attack patterns — including AI crawlers distributed across large residential
proxy networks.

---

## Modernization

- **Java 21**: The project now requires and is built against Java 21 (up from Java 17). The
  `pom.xml` and `Dockerfile` have been updated accordingly.
- **JUnit 5**: The entire test suite has been migrated from JUnit 3 to JUnit 5 (including
  Surefire plugin configuration), resulting in cleaner, more expressive tests and better IDE
  integration.
- **Tomcat base image**: The Docker base image has been updated to `tomcat:10.1.60-jre25-temurin-noble`,
  tracking the latest stable Tomcat 10.1 release.
- **Modern time API**: Replaced legacy `Calendar` usage with `System.currentTimeMillis()` throughout
  the codebase.

---

## Bug Fixes & Concurrency Improvements

- **Thread-safe monitor slot storage**: Replaced string-based slot keys with `long` identifiers and
  switched slot storage to `AtomicReferenceArray`, eliminating subtle race conditions during slot
  rollovers under concurrent load.
- **Lock-free counter operations**: Replaced synchronized `LinkedHashMap` with concurrent collections
  and a custom non-blocking LRU eviction strategy. Counter increments now use `LongAdder` instead of
  `AtomicLong` to reduce contention under high write pressure.
- **Memory-efficient `AntiDoSCounter`**: Replaced `AtomicLong` wrapper objects with `VarHandle`
  access on primitive `volatile` fields, reducing per-counter heap allocation and improving
  cache-line locality.
- **Safe asynchronous eviction**: Conditional map removals prevent the background eviction task from
  accidentally removing a counter that has already been re-inserted by a concurrent request thread.
- **Precise LRU tracking**: LRU timestamps in `AntiDoSCounter` now use `System.nanoTime()` for
  monotonic, high-resolution ordering — avoiding skew from wall-clock adjustments.

---

## New Features

- **IPv4 and IPv6 subnet aggregation** (`ipv4SubnetMask` / `ipv6SubnetMask`): All requests from
  within a configured subnet (e.g. `/24` for IPv4, `/64` for IPv6) now share a single rate-limiting
  counter. This directly counters botnets and residential proxy networks that rotate through many IP
  addresses within the same address block. Accepts CIDR prefix integers, CIDR notation strings, and
  dotted-decimal netmask strings.
- **Server-wide blocking** (`serverWideBlocking`): When enabled, an IP address or subnet that
  exceeds the rate limit on `relevantPaths` is blocked across *all* server paths, not just the
  monitored ones. The detection scope (counting) and the enforcement scope (blocking) are now fully
  decoupled. Whitelisted paths and IPs remain accessible regardless.
- **Separate blocked IP cache** (`maxBlockedIPCacheSize`): Blocked IPs are now tracked in a
  dedicated cache, separate from the active (unblocked) IP cache. This prevents a flood of new
  unique attacker IPs from flushing known-blocked attackers out of memory.
- **Configurable HTTP status code** (`httpStatusCode`): The status code returned for blocked
  requests can now be set explicitly. The default is `429 Too Many Requests` (RFC 6585); set
  `httpStatusCode="403"` to restore legacy behavior.
- **`Retry-After` header**: When responding with HTTP 429, the valve now automatically includes a
  standards-compliant `Retry-After` header indicating the exact remaining seconds of the current
  blocking slot. This helps well-behaved API clients and crawlers back off gracefully.

---

## Performance Improvements

- **Asynchronous batch eviction with circuit breaker**: For large caches (`maxIPCacheSize > 500`),
  the valve now activates a non-blocking asynchronous eviction mode. Tomcat request threads are
  never stalled waiting for cache cleanup. A background daemon trims the active cache to a 90%
  low-watermark. If an extreme flood of unique IPs overwhelms the eviction worker and the cache
  reaches a 120% hard cap, new unknown IPs are evaluated pass-through without being stored —
  protecting JVM heap and thread pool from exhaustion while continuing to track and enforce blocks
  on previously known IPs.
- **Log throttling** (`AntiDoSLogThrottler`): Under massive DDoS conditions, logging every blocked
  request can saturate disk I/O and create thread contention. A new lock-free log rate limiter caps
  block-log output at 20 messages per second. Suppressed messages are counted and summarized in a
  single aggregated line at the start of the next interval.

---

## Interactive Configuration & Analysis Tool

A self-contained, browser-based configuration helper and traffic simulator has been added to the
repository: [`anti-dos-valve-config-helper.html`](https://github.com/ihbrune/Anti-DoS-Valve/blob/master/anti-dos-valve-config-helper.html).

Open it directly in any modern browser — no server or external dependencies required. It provides:

- **Interactive XML Generator & Presets**: Choose from ready-made presets (e.g. *Production
  Standard*, *Aggressive Bot Defense*, *Marking Mode*), customize parameters interactively, and
  generate ready-to-paste `server.xml` snippets with live validation and cache mode diagnostics
  (Sync LRU vs. Async Batch), including an estimated memory consumption display.
- **Single-Client Simulator**: Visualizes the rolling slot window, lookback retention, permitted
  burst capacity, and sustainable continuous request rates for an individual visitor or attacker
  across 49 consecutive time slots.
- **Fleet & DDoS Multi-IP Simulator**: Models high-concurrency traffic from hundreds or thousands
  of simultaneous clients and botnets. Evaluates memory pressure in real time, visualizes Active
  and Blocked Cache fill levels against safety thresholds (90% low-watermark and 120% circuit-
  breaker hard cap), and highlights security risks such as unblocking leaks when the blocked cache
  overflows.
