# What is the Anti-DoS Valve?

This project implements a Tomcat valve that enforces dynamic access rate limits on requests from individual IP addresses or subnets. This helps prevent Tomcat servers from becoming overloaded by DoS attacks or aggressive web crawlers, or at least mitigates their impact.

The valve cannot, of course, provide complete protection against every kind of malicious overload. The goal is rather to provide a simple, easy-to-use overload protection mechanism that can be deployed quickly and with minimal effort, introduces very little overhead in Tomcat, and is particularly effective at slowing down aggressive web crawlers.

For fleet-wide monitoring and forensics across many valve instances, the repository also contains the optional (preview) **[Anti-DoS Collector](collector/README.md)**; the valve works fully standalone without it.

The valve is highly configurable and also provides options to permanently block specific IP addresses or subnets, or to exclude trusted IP addresses and subnets from blocking altogether.

A key goal during development was comprehensive unit test coverage to ensure the correct functioning of this code at a central point in the Tomcat server.

A configuration helper including a simulation tool is provided in the project, and the valve's status can be monitored and its configuration adjusted at runtime via JMX and a web-based status page.

A Dockerfile is included to run Tomcat with the valve using minimal setup.

# Supported Tomcat Versions

Since version 1.4, the valve is built against Tomcat 10.1 libraries. This means it makes use of the <strong>jakarta.servlet.\*</strong> packages. Versions prior to 1.3.0 of the valve were tested on Tomcat 7.0, 8.0, and 9.0, using the legacy <strong>javax.servlet.\*</strong> packages.

Since version 1.6.0, Tomcat 9 compatibility is provided by shading the valve code with javax.servlet. The section below "[Installation and Setup](#installation-and-setup)" describes how to use the valve with Tomcat 9.

# Project Structure (Multi-Module Build since 1.8.0)

> [!IMPORTANT]
> **Build systems that only need the valve must be adapted.** After version 1.7.0 the repository was converted from a single-module project into a Maven multi-module build with the parent POM `org.henbru.antidos:anti-dos-parent` in the repository root. The valve now lives in the submodule [`valve/`](valve/) (artifact `anti-dos-valve`), so its build output moved from `target/` to `valve/target/`.
>
> If your scripts, CI jobs, Dockerfiles or deployment tooling build or copy the valve from this repository, please:
> * build only the valve module: `mvn package -pl valve` (add `-am` if you rely on the parent POM);
> * pick up the JARs from `valve/target/` (`anti-dos-valve-<version>.jar` and `anti-dos-valve-<version>-tomcat9.jar`);
> * update any hard-coded paths such as `target/anti-dos-valve-*.jar`.
>
> Alternatively, use a prebuilt JAR from a GitHub Release. The valve module itself still has zero runtime dependencies.

| Module | Purpose |
| :--- | :--- |
| [`valve/`](valve/) | The Tomcat valve (this README). Zero runtime dependencies, Tomcat 10+ and Tomcat 9 builds. |
| [`collector/`](collector/README.md) | Optional fleet monitoring and forensics service (preview). |
| [`benchmark/`](benchmark/README.md) | JMH performance harness and traffic simulator. |
| [`docker/`](docker/README.md) | Demo Tomcat environment. |

# Implementation of Dynamic Access Rate Limiting

The goal of the implementation was to create a flexible solution that maintains low complexity and minimal overhead on the server.

To determine whether a specific IP address or subnet currently exceeds the allowed request rate, a time-slot model is used: the internal Anti-DoS Monitor divides the monitoring period into successive, non-overlapping slots of a fixed length. For example, with a 1-minute slot length, the slots cover periods such as:

* 12:00:00 to 12:00:59
* 12:01:00 to 12:01:59
* 12:02:00 to 12:02:59
* 12:03:00 to 12:03:59
* …

To determine whether an IP address or subnet has made too many requests, the monitor first checks the requests that occurred within the current slot using a simple counter. Compared to a sliding-window approach without slots, this avoids the overhead of storing individual request timestamps.

For this reason, even during a DoS attack with thousands of requests in a short time, the monitoring overhead is not significantly higher than during normal operation. The drawback of fixed slots is that historical context is lost as soon as a new slot begins. To address this, the monitor provides an option to carry over counts from previous slots.

This transfer mechanism calculates the average number of requests counted in recent slots. A configurable fraction of this average is then carried over into the new slot. Depending on the setting, the Anti-DoS Monitor can 'forget' earlier traffic spikes very quickly or retain them over a longer period.

The Anti-DoS Monitor structure looks like this:

* Current slot: 12:03:00 to 12:03:59
  * Last registered IP address: 123.0.0.1
    * Number of requests in this slot so far: 5
    * Number of retained requests from previous slots: 0
  * Previously registered IP address: 123.0.0.2
    * Number of requests in this slot so far: 1
    * Number of retained requests from previous slots: 3
  * …
* Previous slot: 12:02:00 to 12:02:59
  * ...
* …

The maximum number of allowed requests per slot for an IP address or subnet is compared against the sum of current requests plus the retained requests from previous slots. If this sum exceeds the limit, access is blocked for the remainder of the current slot. When an IP address or subnet is blocked, all of its requests are answered with HTTP status code 429 (Too Many Requests) by default (or the status code configured via `httpStatusCode`, e.g. 403 Forbidden for legacy behavior).

# Production Experience

In its first version (2016), the valve was developed to protect a Tomcat server farm processing more than 1,000,000 requests per day. The valve was in production use there for several months before the code was published on GitHub. During this time, it demonstrated its stability and successfully mitigated DoS attacks from individual servers and small botnets.

In subsequent years, the valve helped protect the same servers in situations where more than 50% of all incoming requests had to be blocked and malicious peak loads reached thousands of requests per second. The valve's implementation proved lightweight and fast enough to keep the servers afloat and serving legitimate traffic without interruption.

In 2026, new traffic patterns from AI crawlers—partly routed through residential proxy networks—overwhelmed the valve due to the sheer volume of unique IP addresses used. The valve was subsequently re-engineered to include subnet aggregation to counter these threats effectively.

# Installation and Setup

Here are the steps to set up and activate the valve:

1. Clone the project from GitHub and build the JARs with Maven: `mvn package -pl valve` (or `mvn install -pl valve`; plain `mvn package` additionally builds the collector and benchmark modules). Both variants are generated automatically in `valve/target/`:
   * **Tomcat 10 / 11 (Jakarta EE):** `anti-dos-valve-<version>.jar`
   * **Tomcat 9 (`javax.servlet`):** `anti-dos-valve-<version>-tomcat9.jar`
2. Make the appropriate JAR available in Tomcat. For example, copy it into `<CATALINA_HOME>/lib/` (probably alongside your JDBC drivers).
3. In `server.xml`, configure the valve inside the appropriate `<Host>` element (see example below).
4. Ensure logging is enabled so that blocked requests are logged (this is already enabled in the default configuration).

The valve is now active!

You can test its functionality using a non-existent URL to avoid impacting real applications. For testing, configure very low thresholds and trigger rapid reloads in your browser until the valve blocks your requests. The following sample configuration can be used for such a test:

        <Valve className="org.henbru.antidos.AntiDoSValve"
                monitorName="TEST-VALVE"
                relevantPaths="/valvetest"
                maxIPCacheSize="50"
                numberOfSlots="10"
                slotLength="30"
                allowedRequestsPerSlot="5"
                shareOfRetainedFormerRequests="0"
        />
        
In this example, the test path is `/valvetest`. Starting from the 6th request, access will be blocked and a corresponding message will appear in the server log.

## Docker Setup

The `docker/` directory contains a Dockerfile and sample commands to run a Tomcat server with the valve pre-configured in a container image. You can use this as a boilerplate for your own projects and as an environment to test your changes with minimal effort.

# Valve Configuration

The main challenge when configuring the valve is finding the right settings for your specific server. You need to strike the right balance: settings that are too strict might lock out legitimate users, settings that are too lenient leave attackers unchecked, and settings that retain too much data consume excessive memory and slow down the Tomcat server.

To find the right configuration, analyze your current server access logs (HTTP/HTTPS), paying particular attention to:

* What is the normal request rate per day / hour / minute / second?
* What are the highest request volumes generated by individual IP addresses?
* Which IP addresses generate heavy traffic? Which of these belong to internal services, and which belong to search engines?
* Depending on your Tomcat application, it may make sense to analyze different application paths separately. Requests for static assets like images or stylesheets are generally less critical than requests for dynamic resources.
* How many requests does a user's browser generate on a first visit, and what types of requests are they?

Standard Unix command-line tools like `grep`, `awk`, `sort`, `uniq`, and `wc` will get you very far when analyzing log files. You don't need a 100% exact figure (traffic varies day to day anyway), but rather a solid baseline understanding of the traffic on your server. If you don't have access logging enabled yet, now is the time to turn it on.

Besides knowing your normal traffic profile, it is also important to estimate the request rate an attacker would need to cause an overload. The smaller the gap between regular traffic and server capacity, the more precisely the Anti-DoS Valve needs to be tuned.

Another way to get some knowledge about the traffic profile of your server is to use the valves simulation mode. In this mode the valve is not blocking any requests, but is logging the requests as it would do in normal operation. You can then analyze the logs to understand the traffic profile of your server.  Use parameter "mode" and set it to "simulation".  Use parameter "relevantPaths" and set it to "all".

Once you have identified the traffic profile values, you can craft your valve configuration using the parameters described below.

## Interactive Configuration Helper & Traffic Simulator

To simplify sizing, tuning, and understanding the valve's behavior, the repository includes a self-contained, browser-based tool: [**anti-dos-valve-config-helper.html**](https://github.com/ihbrune/Anti-DoS-Valve/blob/master/anti-dos-valve-config-helper.html) (open it directly in your web browser without requiring a server or external dependencies).

It provides:
* **Interactive XML Generator & Presets:** Choose from presets (e.g. Production Standard, Aggressive Bot Defense, or Marking Mode), customize parameters, and generate ready-to-use Tomcat `server.xml` snippets with live validation and cache mode diagnostics (Sync LRU vs. Async Batch).
* **Single-Client Simulation:** Deep-dive into how the rolling slot window, lookback retention (`shareOfRetainedFormerRequests`), permitted burst capacity before the first block, and sustainable continuous rates affect an individual visitor or attacker over 49 consecutive time slots.
* **Fleet & DDoS Multi-IP Simulation:** Model high-concurrency traffic from hundreds or thousands of simultaneous clients and botnets. It evaluates memory pressure in real time, visualizes Active and Blocked Cache fill levels against safety thresholds (including the 90% low-watermark eviction trigger and 120% circuit-breaker hard-cap), and highlights security risks such as unblocking leaks when the blocked cache overflows.

## Request Evaluation Pipeline

When an incoming HTTP request reaches the valve, it is processed in two distinct phases: **Ingress Evaluation (Pre-Processing & Access Decision)** and **Egress Inspection (Post-Processing & Session Learning)**.

### Phase 1: Ingress Evaluation (Pre-Processing)

0. **Internal Status Endpoint (`statusUri`)**: Does the request URI match the configured `statusUri`?
   * **Yes**: The request is intercepted **immediately** by the valve and never reaches the web application or downstream valves:
     * **IP Whitelist (`statusAllowedIPs`)**: If configured, the client IP must match this pattern; otherwise &rarr; **404 Not Found**.
     * **Authentication**: Token must be valid (via `?token=...` or `Authorization: Bearer <token>`):
       * **Valid Token**: **Allow (200 OK)** and render the dashboard (HTML or JSON). Valid status queries are never counted in DoS counters. An administrator with the correct token is granted access **even if their IP address is currently blocked on other application paths** (e.g. after testing rate limits).
       * **Invalid or Missing Token**: If the client IP is already blocked by the DoS monitor &rarr; **Block (HTTP error code, e.g. 429)**. If not yet blocked, the failed attempt is recorded in the monitor as an asymmetric brute-force defense &rarr; **401 Unauthorized**.
     * Request execution finishes here (`return`).
   * **No**: The request continues down the standard pipeline below.

0.1. **Visitor & Authentication Context Lookup**:
   * **Visitor Cookie (`visitorCookieEnabled="true"`)**: If an upstream Valve hasn't already validated the visitor token, the Valve checks for the presence and validity of the visitor cookie (`_adv`). It attaches `org.henbru.antidos.RETURNING_VISITOR` and `org.henbru.antidos.VISITOR_CONTEXT` request attributes for all downstream components.
   * **Authentication Session Tracking (`authTrackingMode="COOKIE"`)**: If an upstream Valve hasn't already checked authentication, the Valve extracts `authCookieName` from incoming `Cookie` headers and checks if its salted 64-bit hash exists in the server-wide `AntiDoSAuthSessionCache`. It attaches `org.henbru.antidos.AUTHENTICATED` (`true`/`false`) as a request attribute.

1. **Static Blacklist (`alwaysForbiddenIPs`)**: Does the client IP address match the regular expression pattern? &rarr; **Block (HTTP error code)**.  
   *(Evaluated directly on the individual client IP address string; by default not counted in the dynamic rate monitor, or registered as BLOCKED with limit 0 when `trackAlwaysForbiddenInMonitor="true"`).*
2. **Static Whitelist (`alwaysAllowedIPs`)**: Does the client IP address match the regular expression pattern? &rarr; **Allow**.  
   *(Evaluated directly on the individual client IP address string; request is not counted in the dynamic rate monitor).*
3. **Path Whitelist (`nonRelevantPaths`)**: Does the request URI match `nonRelevantPaths`? &rarr; **Allow**.  
   *(Evaluated before `relevantPaths`; request is not counted; bypasses rate limiting for health-checks or static error pages even if the client IP or its subnet is currently blocked).*
3b. **Auth Scope Filter (`relevantAuthScope`)**: Does the request match the configured authentication scope?
   * If `relevantAuthScope="AUTHENTICATED_ONLY"` and the request is unauthenticated &rarr; **Allow** *(bypasses rate limiting; request is not counted in the monitor)*.
   * If `relevantAuthScope="UNAUTHENTICATED_ONLY"` and the request is authenticated &rarr; **Allow** *(bypasses rate limiting; request is not counted in the monitor)*.
   * If `relevantAuthScope="ALL"` (default) or matches the scope &rarr; continues to step 4.
4. **Detector Match (`relevantPaths`)**: Does the request URI match `relevantPaths`?
   * **Yes**: The client IP is resolved to a counter key — either the **individual IP address** or the **aggregated CIDR subnet** (if `ipv4SubnetMask` or `ipv6SubnetMask` is configured). The request is registered and counted in the rate limiting monitor (tracking returning-visitor and authenticated status). If the threshold for this counter key is exceeded (or already locked) &rarr; **Block**; otherwise &rarr; **Allow**.
5. **Server-Wide Enforcement (`serverWideBlocking`)**: If the URI does *not* match `relevantPaths`, but `serverWideBlocking="true"` is enabled:
   * Is the client IP address (or its aggregated subnet) currently blocked by the monitor? &rarr; **Block** (read-only check; the request is not counted and creates no cache entries).
6. **Default / Unmonitored**: If the URI does *not* match `relevantPaths` and the client IP address (or its subnet) is not blocked &rarr; **Allow** (neither counted nor blocked).

### Phase 2: Downstream Execution & Egress Inspection (Post-Processing)

If the request is allowed (or if the Valve runs in `simulationMode="true"`):
1. **Downstream Forwarding**: The request is passed to the next component in Tomcat's pipeline via `getNext().invoke(request, response)`.
2. **Visitor Cookie Emission**: If the visitor token was missing or nearing expiration, a refreshed `Set-Cookie` header is appended to the response.
3. **Login Session Learning (`authLoginPaths`)**:
   When `authTrackingMode="COOKIE"` is enabled, the Valve inspects outgoing responses from the web application:
   * **Endpoint Filter (`authLoginPaths`)**: Does the request URI match the configured `authLoginPaths` regex (e.g. `^/trust$`)?
   * **HTTP Status Check**: Did the application respond successfully (`200 <= status < 400`, including redirects)?
   * **Session Registration**: If the response contains a `Set-Cookie` header matching `authCookieName` (e.g. `AUTH_COOKIE`), the Valve computes its salted 64-bit hash and registers it in `AntiDoSAuthSessionCache`. If `Max-Age` is specified, it sets the session lifetime accordingly (or purges the session if `Max-Age <= 0`).

> [!NOTE]
> **Interplay between `authLoginPaths`, `nonRelevantPaths`, and `relevantPaths`:**
> * **When `authLoginPaths` matches `nonRelevantPaths`**: Authentication callbacks (e.g. `/trust`) bypass DoS rate-limiting counters completely, preventing legitimate SSO login roundtrips from being accidentally blocked. When the backend completes the handshake and issues the cookie, the Valve **still inspects the response and registers the session**.
> * **When `authLoginPaths` matches `relevantPaths`**: Authentication endpoints are counted against the Valve's rate-limiting threshold (useful to protect standard password login forms against brute-force or credential stuffing attacks). If a client is blocked (HTTP 429), the request is halted before reaching the backend and no session cookie is registered.

### Scope: Individual IP Address vs. Subnet Aggregation

Understanding how the valve identifies clients is important when subnet aggregation is active:

* **Static IP Rules (`alwaysForbiddenIPs`, `alwaysAllowedIPs`)**:  
  Operate strictly on the **individual client IP address** string, before and independently of any subnet mask settings. This makes it possible, for example, to whitelist a specific administrator workstation (`192.168.1.99`) so it is never locked out, even if its entire parent subnet (`192.168.1.0/24`) is currently blocked by dynamic rate limiting.
* **Dynamic Rate Limiting (`AntiDoSMonitor`) & `serverWideBlocking`**:  
  Operate on the resolved counter key:
  * **Individual IP address (default)** when no subnet mask is defined (`ipv4SubnetMask=32`, `ipv6SubnetMask=128`).
  * **Aggregated subnet** when a subnet mask is defined (e.g. `ipv4SubnetMask="24"` or `ipv6SubnetMask="64"`). In this case, all client IPs within that subnet share a common request quota, and when the limit is exceeded, the entire subnet is blocked together.

## monitorName

An optional parameter to name the monitor instance (available since version 1.1). If you run more than one instance of the valve/monitor, this parameter is required to distinguish their configurations. It is also included in log messages. See the section on multi-instance configurations below.

## description

An optional parameter providing an explanatory description of the valve instance (e.g. `description="Rate limiter for public API endpoints"`). When configured, this text is displayed in the Monitoring Status dashboard (both overview and detail views) to explain the purpose of the valve.

## alwaysForbiddenIPs

An optional regular expression defining IP addresses that are always blocked. This option (and `alwaysAllowedIPs`) operates independently of the dynamic rate limiter: matched IPs are unconditionally blocked or allowed.

*Tip:* You can use [RegexPlanet](http://www.regexplanet.com/advanced/java/index.html) to test Java regular expressions.

*Tip 2:* If you only need this static blocking feature, you can use Tomcat's built-in [Remote Address Valve](https://tomcat.apache.org/tomcat-10.0-doc/config/valve.html#Remote_Address_Valve).

## trackAlwaysForbiddenInMonitor (optional)

Available since version 1.8.0 (default: `false`): Controls whether requests blocked by `alwaysForbiddenIPs` are also registered inside the dynamic `AntiDoSMonitor` and exposed in the `BLOCKED` category on the internal status dashboard and Collector API.

* **Default (`trackAlwaysForbiddenInMonitor="false"`)**: Matches are rejected immediately on the high-performance fast path without allocating monitor slot counters. Only the aggregated lifetime counter `alwaysForbiddenBlockedRequests` is incremented.
* **Enabled (`trackAlwaysForbiddenInMonitor="true"`)**: Requests from forbidden IPs are immediately locked and registered in the current slot's `blockedClients` cache with an effective limit of 0 (Honeypot-like zero tolerance). This captures individual attacking IP addresses, per-slot hit counts, and forensic sample metadata (HTTP method, request URI, and User-Agent) for full visibility in the Collector monitoring dashboard.

## alwaysAllowedIPs

An optional regular expression defining IP addresses that are always allowed access. This setting is evaluated after *alwaysForbiddenIPs*.

This parameter can be used, for example, to whitelist your corporate intranet or VPN so internal users are never blocked. If a specific internal IP needs to be blocked later, that can still be done via *alwaysForbiddenIPs*.

Both *alwaysForbiddenIPs* and *alwaysAllowedIPs* apply to all requests processed by the Tomcat host. Requests handled by these rules are not counted in the dynamic Anti-DoS Monitor slots.

## relevantPaths

A regular expression defining which request paths should be monitored by the dynamic rate limiter. While technically optional, it is almost always configured unless you are only using *alwaysForbiddenIPs*. This setting provides several key benefits:

* Rate limiting can be restricted to the endpoints that are actually vulnerable to attack. On servers hosting both public and internal applications, monitoring can be limited to public-facing URLs, reducing monitoring overhead while allowing tighter limits.
* Monitoring can focus on resource-intensive endpoints (such as servlets and APIs) while excluding static assets (CSS, JS, images). Excluding static files significantly reduces the risk of false positives for legitimate users.

Example values:

* `".*"`: All requests are processed by the Anti-DoS Monitor.
* `"/manager.*"`: Only requests to the Tomcat Manager application are monitored; all other requests bypass the valve.

### Interaction with `nonRelevantPaths` and `statusUri`

* **Precedence of `nonRelevantPaths`**: If a request URI matches both `relevantPaths` and `nonRelevantPaths`, `nonRelevantPaths` takes precedence and the request is **not** monitored or rate-limited.
* **Precedence of `statusUri`**: Requests matching `statusUri` are intercepted at the valve entry point before `relevantPaths` is evaluated. Even if `relevantPaths=".*"` matches all URLs, `statusUri` is handled by the internal status dashboard and is not subject to standard application request quotas.

## nonRelevantPaths

Available since version 1.4.0 and evaluated before *relevantPaths*: allows specific URL paths to be excluded from monitoring so they are never rate-limited.

This is especially helpful when an entire path hierarchy should be protected, except for a few specific endpoints. For example:

* `relevantPaths="/myexampleapi/.*"` protects all API endpoints.
* `nonRelevantPaths="/myexampleapi/status"` keeps only the health/status endpoint accessible without rate limiting. Without `nonRelevantPaths`, you would have to enumerate every other endpoint individually in `relevantPaths`, and remember to update it whenever a new endpoint is deployed. With `nonRelevantPaths`, newly added endpoints are protected automatically.

### Interaction with Other Parameters

* **`relevantPaths`**: `nonRelevantPaths` is checked before `relevantPaths`. If a path matches `nonRelevantPaths`, it immediately bypasses rate limiting, regardless of `relevantPaths`.
* **`statusUri`**: The internal status endpoint `statusUri` does **not** need to be added to `nonRelevantPaths`. `statusUri` is intercepted prior to the path evaluation pipeline.
* **`serverWideBlocking`**: Even when `serverWideBlocking="true"` is enabled, paths matching `nonRelevantPaths` remain reachable by all clients (including clients that are currently blocked on other endpoints).

## serverWideBlocking (optional)

Available since version 1.5.0 (default: `false`): Decouples the **detection scope** (where requests are counted) from the **enforcement scope** (where the block takes effect).

By default (`serverWideBlocking="false"`), only requests matching `relevantPaths` are monitored, and only requests matching `relevantPaths` can be blocked. In this default mode, if an attacker exceeds the limit on a protected endpoint (e.g. `/login`), they are blocked on `/login`, but could still access other unmonitored URLs.

When `serverWideBlocking="true"` is enabled:
* The rate limit counters still only count requests on `relevantPaths` (avoiding false positives from uncritical endpoints or static assets).
* However, once an IP address (or its aggregated subnet) exceeds the threshold on `relevantPaths` and is blocked, that block is enforced **server-wide across all paths**.
* Requests to unmonitored paths from non-blocked clients are passed through without increasing rate limit counters or consuming cache space.
* Whitelisted paths in `nonRelevantPaths` (such as `/status`, `/health`, or error assets) and `alwaysAllowedIPs` still remain accessible.

The following settings control dynamic rate limiting in the Anti-DoS Monitor. Keep in mind that some of these parameters interact with each other:

## maxIPCacheSize

Defines the maximum number of active (unblocked) IP addresses tracked in a slot. This limit prevents the memory usage of the Anti-DoS Monitor from growing unbounded.

When an IP address exceeds the allowed request limit and is blocked, it is moved from the active cache to a separate blocked IP cache so it no longer consumes space in the active cache. This ensures that a flood of requests from many distinct unblocked IPs (e.g. distributed botnets or scanners) cannot flush blocked attackers out of the cache.

### Eviction Behavior & Asynchronous High-Throughput Mode

How cache eviction is handled depends automatically on the configured cache size:

* **Small Caches (`maxIPCacheSize <= 500`):**  
  Uses synchronous Least-Recently-Used (LRU) eviction. When capacity is exceeded, the least recently active entries are immediately removed. For small cache sizes (such as in local tests or lightweight setups), this is exact and deterministic with negligible CPU overhead.
* **Large Caches (`maxIPCacheSize > 500`) — Asynchronous Batch Eviction & Circuit Breaker:**  
  When scaling to tens or hundreds of thousands of concurrent IPs (e.g. against residential proxy attacks or large subnets), the valve automatically activates a non-blocking asynchronous eviction mechanism:
  * **Asynchronous Hysteresis (Batch Eviction):**  
    When the active cache reaches capacity (100%), Tomcat request worker threads are **never** blocked waiting for eviction scans. Instead, an asynchronous daemon task is triggered in the background to clean up the oldest entries down to the low-watermark (90% of capacity). Subsequent HTTP requests continue with sub-microsecond latency and zero lock contention.
  * **Circuit Breaker (120% Hard-Cap Protection):**  
    If an extreme attack floods new unique IP addresses faster than the background worker can clean up, the cache reaches a hard cap of 120% capacity (`HARD_CAP_RATIO = 1.2`). In this scenario, completely new IP addresses are evaluated on-the-fly without being permanently inserted into the map (pass-through mode). This protects the JVM heap and Tomcat thread pool from exhaustion, while previously known or blocked IPs remain strictly tracked and enforced.

## maxBlockedIPCacheSize (optional)

Defines the maximum number of blocked IP addresses tracked in a slot. This prevents unbounded memory growth during distributed attacks involving large numbers of attacking IPs. If omitted, it defaults to the value of **maxIPCacheSize**.

Blocked IP addresses continue to count subsequent requests even after being blocked, and these counts are factored into the retained request calculations of subsequent time slots to prevent attackers from immediately unblocking when a new slot begins.

Like *maxIPCacheSize*, if *maxBlockedIPCacheSize* exceeds 500, it utilizes asynchronous batch eviction with a 90% low-watermark and a 120% hard-cap. If the blocked cache reaches its hard-cap during an aggressive distributed attack, newly locked counters are safely retained in the active cache rather than dropped, guaranteeing that attackers cannot evade rate limits by attempting to flood or poison the blocked cache.

## ipv4SubnetMask (optional)

Configures subnet aggregation for IPv4 addresses to protect against distributed botnets, proxy networks, and cache-flushing scans where attackers distribute requests across multiple IP addresses within the same subnet.

When set to a prefix length smaller than 32 (e.g. `24` for `/24`), all requests originating from that subnet (such as `192.168.1.10` and `192.168.1.20`) are aggregated under a shared counter key (e.g. `192.168.1.0/24`). This prevents botnets from consuming multiple cache entries or evading rate limits by rotating IP addresses within the same subnet.

Accepts:
* CIDR prefix integer (1 to 32), e.g. `24`
* CIDR notation string, e.g. `"/24"`
* Dotted-decimal netmask string, e.g. `"255.255.255.0"`
* `32` or `-1`: Disables IPv4 aggregation (default behavior; each IP address is tracked individually).

*Performance & Telemetry note:* When `ipv4SubnetMask` is set to `24` (the recommended setting for bot defense and residential proxy detection), the Valve maintains an exact, lock-free 256-bit bitmask (32 bytes per subnet counter) counting the number of distinct client IP addresses that visited the subnet. This provides the Anti-DoS Collector with exact distinct-IP metrics for its 2D cluster scatterplot without memory explosion.

*Note:* Whitelisted IP addresses configured in *alwaysAllowedIPs* (e.g. `127.0.0.1` or specific internal machines) are evaluated prior to rate limiting and subnet aggregation, so individual whitelisted IPs remain accessible even if their subnet would otherwise be blocked.

## ipv6SubnetMask (optional)

Configures subnet aggregation for IPv6 addresses. In IPv6 networks, attackers often have access to vast address pools (e.g. entire `/64` subnets) and can generate virtually unlimited unique IP addresses to easily bypass per-IP rate limits and flush cache entries.

When set to a prefix length smaller than 128 (e.g. `64` for `/64`), all IPv6 addresses within that prefix share the same rate-limiting counter (e.g. `2001:db8:abcd:12::/64`).

Accepts:
* Prefix length integer (1 to 128), e.g. `64` or `48`
* CIDR notation string, e.g. `"/64"`
* `128` or `-1`: Disables IPv6 aggregation (default behavior).

## collectorIntegration (optional)

Controls whether extended telemetry (such as distinct client IP tracking in aggregated subnets) is collected for ingestion by an Anti-DoS Collector instance:

* `auto` (Default): Automatically activates extended telemetry for a rolling 2-minute lease whenever an Anti-DoS Collector queries the Valve's status endpoint (`?format=json`). When no collector is polling, extended telemetry is dormant with zero overhead.
* `true`: Permanently enables extended telemetry from the moment Tomcat boots.
* `false`: Permanently disables extended telemetry.

## activeSampleThreshold (optional)

Available since version 1.8.0 (default: `0` = disabled): Sets the per-slot request count threshold above which an active (allowed) client or subnet counter captures a sample request snapshot (HTTP method, request URI, and User-Agent) for forensic telemetry.

* **Default (`activeSampleThreshold="0"`)**: Request snapshots are captured exclusively when a counter is blocked or marked (`allowed == false`).
* **Active Sampling (`activeSampleThreshold > 0`)**: Once an active counter's combined request count reaches or exceeds this threshold, the first subsequent request captures a sample snapshot without allocating additional memory on following requests. This is especially valuable on wide subnet monitoring valves (e.g. `ipv4SubnetMask="24"` with `activeSampleThreshold="50"`) to diagnose distributed stealth scrapers or horizontal botnet carpet waves that stay below the blocking threshold.

## visitorCookieEnabled (optional)

Available since version 1.7.5, enables cryptographic first-party visitor tracking (*Proof-of-Prior-Visit*) using standard **AES-256-GCM (AEAD)** with zero runtime dependencies. Default: `false`.

When enabled, the Valve automatically issues an unforgeable, compact (~58 characters Base64URL) HTTP cookie to clients. The token contains the client's masked network subnet, an expiration timestamp, and a saturating visit counter. Any bit manipulation or forged cookie causes an immediate AEAD tag mismatch and is rejected before parsing.

### Visitor Cookie Parameters

* `visitorCookieEnabled`: `true` or `false` (default: `false`).
* `visitorCookieName`: Name of the HTTP cookie (default: `"_adv"`). Can be set to any valid cookie name (e.g. `visitorCookieName="my_app_visitor"`). Custom names are dynamically discovered by the status telemetry and the Anti-DoS Collector, which displays `COOKIE: ACTIVE (<name>)` and binds metrics automatically without requiring the default name.
* `visitorCookieSecret`: 256-bit or 128-bit secret key (64 or 32 hex characters, or Base64 string). If omitted, an ephemeral 256-bit AES key is automatically generated on startup (for single-server deployments). In multi-server clusters, configure the same secret key across all nodes to allow instant stateless cross-server validation without database or session replication.
* `visitorCookieTtlSeconds`: Token lifetime in seconds (default: `900` = 15 minutes).
* `visitorCookieRefreshRatio`: Fraction of TTL that must elapse before a refreshed cookie with incremented visit counter is emitted (default: `0.5` = 50% elapsed). This throttling mechanism completely prevents HTTP/2 parallel asset request race conditions and header bloat.
* `visitorCookieSubnetMaskV4`: IPv4 subnet mask prefix bound to the cookie token (default: `24` for `/24`). Prevents botnet operators from sharing cookies across different networks.
* `visitorCookieSubnetMaskV6`: IPv6 subnet mask prefix bound to the cookie token (default: `64` for `/64`).
* `visitorCookiePath`: Cookie `Path` attribute (default: `"/"`).
* `visitorCookieDomain`: Cookie `Domain` attribute (e.g. `"example.com"`). Allows sharing reputation and returning visitor status across multiple subdomains (e.g. `auth.example.com` and `app.example.com`). Defaults to `null` (host-only cookie per RFC 6265).
* `visitorCookieSameSite`: Cookie `SameSite` attribute (`"Lax"`, `"Strict"`, or `"None"`, default: `"Lax"`).
* `visitorCookieSecure`: `"auto"` (sets `Secure` if request is HTTPS or `X-Forwarded-Proto: https`), `"true"`, or `"false"` (default: `"auto"`).

### Inter-Valve Request Attributes & Multi-Valve Inheritance

The Valve automatically populates request attributes for all downstream Valves, filters, and servlets:
* `org.henbru.antidos.RETURNING_VISITOR`: `Boolean.TRUE` if the request carried a valid, unexpired cookie matching the client subnet, `Boolean.FALSE` otherwise.
* `org.henbru.antidos.FIRST_CONTACT`: `Boolean.TRUE` if the client was unseen or lacked a valid cookie, `Boolean.FALSE` otherwise.
* `org.henbru.antidos.VISITOR_COUNTER`: `Integer` visit sequence counter extracted from the token (starts at `1`, increments on refreshes up to `65535`).
* `org.henbru.antidos.VISITOR_CONTEXT`: Immutable `AntiDoSVisitorContext` containing validation state, visit counter, and subnet parameters.

> [!NOTE]
> **Automatic Multi-Valve Inheritance in Multi-Tier Setups:**
> If you have multiple Valves configured along Tomcat's pipeline (e.g. at `<Engine>`, `<Host>`, or across several `<Context>` containers), you only need to configure and enable `visitorCookieEnabled="true"` (along with secret and expiration parameters) in the top-level upstream Valve.
>
> When the upstream Valve validates the visitor cookie, it stores the immutable `AntiDoSVisitorContext` in the request attributes. All downstream Valves automatically detect this context and inherit the returning visitor status for their own rate-limiting calculations and monitor counters without any configuration needed (`visitorCookieEnabled` does not even have to be set on downstream Valves). This completely eliminates redundant cookie parsing and cryptographic operations across multi-valve pipelines.

## authTrackingMode (optional) — Authentication Session Tracking

Enables passive tracking of requests originating from authenticated application users without requiring the Valve to understand application-specific session formats, SAML assertions, or cryptographic keys. Default: `"OFF"`.

When `authTrackingMode="COOKIE"` is configured, the Valve monitors responses on the configured login callback endpoint(s) (`authLoginPaths`, e.g. `/trust` for an SSO/SAML assertion consumer service) after downstream execution (`getNext().invoke(request, response)`). Whenever the application responds with a successful or redirect HTTP status (`200 <= status < 400`) and emits a `Set-Cookie` header for `authCookieName` (e.g. `AUTH_COOKIE`), the Valve computes a salted 64-bit hash of the cookie value and registers its expiration timestamp in a shared, server-wide in-memory session cache (`AntiDoSAuthSessionCache`).

On subsequent incoming requests, the Valve checks whether the `Cookie` header contains `authCookieName` and looks up its 64-bit hash in the session cache:
* **Authenticated Request:** If the hash is present and unexpired, the request is counted as authenticated in the IP/subnet counter (`authenticatedCount`), the active time slot (`authenticatedRequests`), and the monitor lifetime total (`totalAuthenticatedRequests`).
* **Session Expiry & Logout Invalidation:** If the `Set-Cookie` header on `authLoginPaths` specifies `Max-Age`, that value determines the session's cache lifetime; otherwise, `authSessionTtlSeconds` is used as a fallback. If `Max-Age <= 0` or the cookie value is empty (e.g. upon logout), the hash is immediately removed from the session cache.

### Authentication Tracking Parameters

| Attribute | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `authTrackingMode` | No | `"OFF"` | Activation mode for authentication tracking. Set to `"COOKIE"` to enable login cookie observation, or `"OFF"` to disable. |
| `authCookieName` | Yes *(when `COOKIE`)* | *(none)* | Name of the HTTP cookie set by the application upon successful login (e.g. `"AUTH_COOKIE"`). |
| `authLoginPaths` | Yes *(when `COOKIE`)* | *(none)* | Regular expression matching the login / SSO callback path(s) where `Set-Cookie` is issued (e.g. `"/trust"` or `"^/trust$"`). Evaluated on all requests passing through the Valve, even if the login path is excluded from rate limiting via `nonRelevantPaths` or omitted from `relevantPaths`. |
| `authSessionTtlSeconds` | No | `900` | Fallback session validity in seconds (`>= 1`) when the `Set-Cookie` header does not include a `Max-Age` attribute (default: `900` = 15 minutes). |
| `maxAuthCacheSize` | No | `50000` | Maximum number of concurrent authenticated session hashes held in the shared server-wide open-addressing cache (`>= 1`). Default `50000` consumes only ~800 KB of heap (16 bytes per slot). |
| `relevantAuthScope` | No | `"ALL"` | Traffic filter controlling which requests this Valve monitors and enforces rate limits on based on authentication state: `"ALL"` (default; monitors both authenticated and unauthenticated traffic), `"AUTHENTICATED_ONLY"` (monitors only authenticated requests; unauthenticated requests bypass rate-limiting), or `"UNAUTHENTICATED_ONLY"` (monitors only unauthenticated requests; authenticated requests bypass rate-limiting). |

### Multi-Valve Cascade & Inter-Valve Request Attributes

Just like Visitor Cookie tracking, Authentication Session Tracking is designed for zero-redundancy operation across a cascade of Valves in the same Tomcat server:
* **Single Configuration Point:** You only need to configure `authTrackingMode="COOKIE"` on **one** Valve in the pipeline (ideally the upstream Valve).
* **Request Attribute Propagation (`org.henbru.antidos.AUTHENTICATED`):** When the upstream Valve verifies a request's login cookie, it sets the request attribute `org.henbru.antidos.AUTHENTICATED` to `Boolean.TRUE` (or `Boolean.FALSE`). All downstream Valves read this attribute in $O(1)$ without re-parsing cookies or re-hashing.
* **Shared Server-Wide Session Cache & Automatic Discovery:** The underlying `AntiDoSAuthSessionCache` is shared across all `AntiDoSValve` instances in the JVM. Even if a downstream Valve processes a path before or independently of the valve that observed `/trust`, it automatically inherits the active Auth Tracking state (`AUTH TRACKING: INHERITED`) and can verify cookies directly against the shared cache.
* **Adaptive Status Dashboard & JSON Telemetry:** The internal Status Dashboard (`/antidos-status`) automatically detects whether any Valve in the server has `authTrackingMode="COOKIE"` enabled. Only when active does it display the `Auth Tracking` status row and the `Authenticated` request columns in the Slot Ring Buffer Timeline, Blocked Clients, and Top Active Clients tables.

### Tiered Rate Limiting via `relevantAuthScope` (Decoupled Multi-Valve Setup)

`relevantAuthScope` enables operators to define independent rate limiting tiers for anonymous visitors versus authenticated users across multiple cascaded Valves:

* **Decoupled Configuration (No Need to Configure Everything in One Valve):** In a tiered multi-valve setup, you do **not** need to configure `authTrackingMode="COOKIE"` on every Valve. A single Valve in the server can observe login cookies (e.g. at `/trust`), while separate Valves in the pipeline enforce different rate limits using `relevantAuthScope`.
* **Example — Tiered Protection Configuration:**
  ```xml
  <!-- Valve 1: Strict rate limiting for anonymous visitors, scrapers & bots -->
  <Valve className="org.henbru.antidos.AntiDoSValve"
         monitorName="Public-Anonymous-Valve"
         authTrackingMode="COOKIE"
         authCookieName="AUTH_COOKIE"
         authLoginPaths="^/trust$"
         relevantAuthScope="UNAUTHENTICATED_ONLY"
         allowedRequestsPerSlot="60" />

  <!-- Valve 2: Relaxed budget for authenticated customers / internal users -->
  <Valve className="org.henbru.antidos.AntiDoSValve"
         monitorName="Customer-Portal-Valve"
         relevantAuthScope="AUTHENTICATED_ONLY"
         allowedRequestsPerSlot="600" />
  ```
  In this configuration:
  1. An unauthenticated scraper hitting the site is evaluated by Valve 1 (strict limit: 60 req/slot). Valve 2 ignores the scraper completely (`relevantAuthScope="AUTHENTICATED_ONLY"`).
  2. When a user authenticates via `/trust`, Valve 1 registers the session in the shared cache.
  3. Subsequent requests from that user carry the valid login cookie: Valve 1 ignores them (`relevantAuthScope="UNAUTHENTICATED_ONLY"`), while Valve 2 monitors them under the relaxed 600 req/slot limit.

### Architectural Design Rationale: Salted 64-Bit Fast Hashing & Primitive Open-Addressing

To track tens of thousands of concurrent login cookies (which may themselves be large encrypted SAML/JWT payloads of several kilobytes) directly inside Tomcat's hot request processing path, `AntiDoSAuthSessionCache` combines a **per-JVM salted 64-bit keyed fast hash** with a **lock-free primitive open-addressing table (`AtomicLongArray`)**:

1. **True Zero Heap Allocation on the Hot Path (No Digest Arrays, No `Long` Autoboxing):**
   * Computing `MessageDigest.getInstance("SHA-256")` requires converting the cookie `String` into a `byte[]` array and allocating a 32-byte digest array plus a wrapper key object on every request. Instead, our 64-bit SplitMix64 / MurmurHash3-64 mixer operates directly on `String.charAt(i)` in CPU registers.
   * Furthermore, storing hashes in a generic `ConcurrentHashMap<Long, Long>` would autobox primitive `long` hashes and expiration timestamps into `java.lang.Long` objects and allocate `Node` wrappers (~80–96 bytes per entry), creating GC pressure on lookups and insertions.
   * To eliminate autoboxing completely without external libraries (such as `fastutil`), `AntiDoSAuthSessionCache` stores interleaved `[hash, expiresAt]` primitive `long` pairs in a flat `AtomicLongArray` with bounded linear probing (up to 16 consecutive slots = 4 CPU cache lines). Both `isValidSession()` and `registerSession()` execute with **zero object allocations**.
2. **Ultra-Compact Memory Footprint (16 Bytes per Session Slot):** Because each slot consists of just two primitive 64-bit `long` values (`hash` and `expiresAt`) in a contiguous array, 10,000 sessions require only ~160 KB and the default capacity of 50,000 sessions requires only **~800 KB** of heap memory, regardless of whether the raw `AUTH_COOKIE` payload is 32 bytes or 4 KB long.
3. **Lock-Free Local TTL Eviction:** When all 16 slots in a bounded linear probe window are occupied by active sessions, `registerSession()` atomically overwrites whichever slot in that 16-slot neighborhood has the earliest `expiresAt` timestamp. This achieves $O(1)$ local TTL eviction within the same CPU cache lines without global eviction locks or `PriorityQueue` allocations.
4. **Protection Against Hash-Flooding (Per-JVM CSPRNG Salting):** At class initialization, `AntiDoSAuthSessionCache` generates two independent 64-bit secret seeds using `java.security.SecureRandom`. Because these 128 bits of key material are unknown to external clients and change on every JVM restart, attackers cannot precompute hash collisions to manipulate probe windows or spoof another session's hash.
5. **Negligible Collision Probability:** By the birthday bound over a $2^{64}$ hash space, the probability that a random forged cookie collides with any of 10,000 active sessions is $\approx 5.4 \times 10^{-16}$ (less than 1 in a quadrillion). Even in that purely theoretical event, the impact is strictly limited to rate-limit accounting in the Valve and never grants application-level authentication.

## slotLength

The duration of a slot in seconds (must be an integer greater than 0). The slot length and *allowedRequestsPerSlot* are closely related:

## allowedRequestsPerSlot

The maximum number of requests permitted within a slot before an IP address or subnet is blocked (must be an integer greater than or equal to 0). As described above, the check evaluates the sum of requests in the current slot plus requests carried over from previous slots.

* **Zero-Tolerance / Honeypot Traps (`allowedRequestsPerSlot="0"`):** Setting this parameter to `0` causes the monitor to block any accessing client immediately on its very first request. When combined with `serverWideBlocking="true"` and `relevantPaths=".*\\.(php|cgi|aspx)$|.*/wp-.*"` (probing paths that never exist on your Tomcat server), probing bots and vulnerability scanners are banned across the entire server upon their first probe attempt.

Increasing *slotLength* should typically be paired with an increase in *allowedRequestsPerSlot* to avoid blocking legitimate users. However, higher limits also give attackers more leeway before a block triggers.

Conversely, setting *slotLength* too low diminishes the advantages of slot-based tracking, as more slots must be maintained and evaluated.

## numberOfSlots

The number of slots the monitor maintains in memory (must be an integer greater than 0). With a value of 1, the monitor retains no memory beyond the active slot. Larger values give the monitor a longer historical 'memory'.

This history is used when requests from earlier slots are factored into evaluating an IP address in the current slot (see *shareOfRetainedFormerRequests*).

## shareOfRetainedFormerRequests (optional)

Defines the degree to which past requests from an IP address or subnet influence its evaluation in the current slot (must be a floating-point value greater than or equal to 0). Since version 1.7.0, this parameter is optional and defaults to `0`.

The monitor calculates the average request count across previous slots and multiplies it by this factor. A higher value penalizes an IP address longer for past traffic spikes, whereas a low value allows a previously blocked IP to make requests again soon after a new slot begins. Example values:

* `0` (Default): No historical request counts are carried over. In this case, *numberOfSlots* should be set to 1 to minimize memory usage.
* `0.5`: 50% of the average request count from past slots is carried over. A value below 1 gives attackers (as well as inadvertently blocked regular users) a fresh request allowance at the start of each new slot.
* `1`: The average past request count is carried over in full. During an ongoing attack, an IP address that consistently exceeded limits in previous slots will be blocked right from the start of the new slot.
* `<numberOfSlots>`: If this factor equals the number of slots, a single past slot with excessive requests is enough to immediately block the IP address in a new slot. Furthermore, several slots where traffic stayed just below the threshold can accumulate and trigger a block. Any value greater than 1 has this effect.

## monitorMode

Since version 1.2.0, the valve offers an alternative operating mode: *marking mode* (detailed below). If omitted, the valve defaults to *blocking* mode (`"BLOCKING"`).

To enable marking mode, set this parameter to `"MARKING"` (case-insensitive).

## simulationMode

Available since version 1.1.0, this option simulates the valve's behavior without actually blocking or marking requests (`false` by default). When set to `true`, it still logs actions, allowing you to gauge the impact of your configuration safely.

## httpStatusCode

Since version 1.4.1, this optional parameter defines the HTTP status code returned when a request is blocked in *blocking* mode. The default is `429` (*Too Many Requests*, per RFC 6585). To retain the legacy behavior of earlier versions, set `httpStatusCode="403"` (*Forbidden*). Any valid HTTP status code between 100 and 599 can be specified.

When responding with status `429`, the valve automatically includes an RFC 6585 / RFC 9110 compliant `Retry-After: <seconds>` HTTP header indicating the exact remaining seconds until the current time slot ends (at least 1 second). This tells well-behaved API clients, mobile apps, and crawlers how long to wait before retrying, preventing futile immediate retries during the blocked window.

## statusUri (optional)

Available since version 1.6.0, specifies the URI path under which the internal status dashboard is served. The path must start with a leading `/` (e.g. `/antidos-status`). If omitted or empty, the dashboard is completely disabled (default). See [Internal Status Dashboard](#internal-status-dashboard) for details.

### Interaction with `relevantPaths`, `nonRelevantPaths`, and Blocked IPs

* **Early Interception**: `statusUri` is intercepted before the request reaches the standard pipeline or the web application. Downstream servlets or valves are not invoked.
* **No Configuration in `nonRelevantPaths` Required**: You do not need to add `statusUri` to `nonRelevantPaths` or exclude it from `relevantPaths`. It is handled completely independently.
* **Multi-Valve Deployments (Place on the First Valve)**: In setups with multiple valves, configure `statusUri` **only on the first valve in the pipeline** (or define a dedicated status valve placed first in `server.xml`). Because Tomcat processes valves sequentially, placing `statusUri` on the first valve ensures dashboard requests are intercepted immediately before any subsequent application valves can inspect, count, or rate-limit them.
* **Access from Blocked IPs**: If an administrator's IP address has been blocked by the valve (for example, while testing rate limits against `relevantPaths`), the administrator can **still access** the status dashboard by providing the valid token. This ensures administrators are never locked out of monitoring the valve. Conversely, requests from blocked IPs with missing or incorrect tokens are immediately rejected with HTTP 429 without performing password verification.

## statusAllowedIPs (optional)

Optional regular expression restricting access to the status dashboard to specific client IP addresses or subnets (e.g. `statusAllowedIPs="127\.0\.0\.1|::1|10\..*"`). Requests from unauthorized IPs receive `404 Not Found`.

## statusPassword (optional)

Access password for the status dashboard. If explicitly configured, it must be at least 10 characters long. If left empty or omitted, a secure random token is automatically generated on server startup and printed to the logs.

## mitigationPassword, mitigationUri, mitigationAllowedIPs (optional) — Dynamic CIDR Mitigation

Available since version 1.8.0: Enables dynamic, TTL-based CIDR subnet blocking on a specific Valve instance, allowing the Anti-DoS Collector (or an operator) to push, extend, or revoke subnet blocks at runtime via HTTP `POST` without restarting Tomcat.

* **`mitigationPassword`** (default: `null` / disabled): Write token/password (minimum 10 characters) that activates dynamic CIDR mitigation on this specific Valve and authenticates incoming `POST` commands. Dynamic blocks are strictly isolated to the Valve instance where `mitigationPassword` is configured (no JVM-wide inheritance), allowing upstream simulation/monitoring Valves to continue observing raw traffic before the blocking Valve rejects it.
* **`mitigationUri`** (optional, falls back to `statusUri`): Dedicated URI path for receiving `POST` mitigation commands (e.g. `mitigationUri="/antidos-mitigate"`). If omitted, `POST` commands are accepted on `statusUri` (when configured on the same Valve).
* **`mitigationAllowedIPs`** (optional regular expression, falls back to `statusAllowedIPs`): Restricts which client IP addresses may send `POST` mitigation commands (e.g. restricting write access exclusively to the Anti-DoS Collector IP while allowing broader read-only access on `statusAllowedIPs`).
* **`mitigationMinPrefixV4`** (default: `16`): Broadest allowed IPv4 prefix length accepted for remotely pushed dynamic blocks (1 to 32). Overly broad blocks (e.g. `/8`) are rejected with `HTTP 400 Bad Request`.
* **`mitigationMinPrefixV6`** (default: `32`): Broadest allowed IPv6 prefix length accepted for remotely pushed dynamic blocks (1 to 128). Overly broad blocks (e.g. `/24`) are rejected with `HTTP 400 Bad Request`.
* **`mitigationMaxTtlSeconds`** (default: `86400` = 24 hours): Upper limit in seconds for dynamic block expiration. Expiration timestamps exceeding `now + mitigationMaxTtlSeconds` are automatically capped to this duration.
* **`mitigationMaxActiveBlocks`** (default: `5000`): Maximum number of simultaneously active dynamic blocks on this Valve. Commands that would exceed this capacity are atomically rejected with `HTTP 409 Conflict`, leaving the existing rule set untouched.

### Precedence & Deterrence Telemetry

1. **Server-Wide Enforcement (`alwaysAllowedIPs` Wins):** Active dynamic CIDR blocks are evaluated in `isRequestAllowed()` immediately after `alwaysAllowedIPs` and **before** `nonRelevantPaths`, `relevantAuthScope`, and `relevantPaths`. Whitelisted IPs in `alwaysAllowedIPs` can never be locked out by a dynamic subnet block.
2. **Prefix Width Safety Guardrail:** The Valve validates incoming dynamic blocks against `mitigationMinPrefixV4` and `mitigationMinPrefixV6`, rejecting broader networks with `HTTP 400 Bad Request`.
3. **Bounded & Self-Expiring TTL:** Every dynamic rule carries an expiration timestamp (`expiresAtMillis`) bounded by `mitigationMaxTtlSeconds`. It ceases blocking at the exact millisecond its TTL expires, even if the Collector becomes unreachable.
4. **Capacity Protection:** `mitigationMaxActiveBlocks` bounds memory usage and blast radius.
5. **Attacker Deterrence Tracking:** Requests rejected by a dynamic CIDR rule are recorded both on the rule entry and in the current `AntiDoSSlot` as a locked counter keyed by the matched canonical CIDR (e.g. `198.51.100.0/24`), including distinct client IPs, distinct User-Agents, and a forensic sample request (`method`, `uri`, `userAgent`).

# Sample Configurations

The configuration shown above can serve as a starting point for your production setup.

You can test the effects of configuration values in the 'Traffic & Attack Simulator' section of [**anti-dos-valve-config-helper.html**](https://github.com/ihbrune/Anti-DoS-Valve/blob/master/anti-dos-valve-config-helper.html), or copy this entire [**Google Sheet**](https://docs.google.com/spreadsheets/d/1eztKVnzjW9xVVia1hDAeLaiiKRAGfNKRFx5lvKkbLBs/edit?usp=sharing) to your own Google account and adjust the fields marked **'set me!'** to see how different parameters affect request thresholds for attackers and regular users.

Finally, define your *relevantPaths* pattern. Ideally, this should cover only endpoints that are publicly accessible and consume noticeable server resources. Here is a real-world example:

        <Valve className="org.henbru.antidos.AntiDoSValve"
                monitorName="MY-VALVE"
                alwaysAllowedIPs="10\.68\.\d+\.\d+|10\.77\.\d+\.\d+"
                relevantPaths=".*(jsp|/download/|/pdf/).*"
                maxIPCacheSize="250"
                numberOfSlots="20"
                slotLength="15"
                allowedRequestsPerSlot="50"
                shareOfRetainedFormerRequests="5"
        />
        
This configuration is similar to the one used in the server farm where the valve was originally deployed. Those servers handled normal traffic of one to two million requests per day on dynamic (servlet-generated) content. Key aspects of this configuration:

* *alwaysAllowedIPs*: Whitelists internal IP ranges so employees on corporate devices are never blocked.
* *alwaysForbiddenIPs*: In production, this contained several IP ranges that had caused repeated issues in the past.
* *relevantPaths*: Matches only dynamic application endpoints. Static assets like CSS, JS, and images are excluded unless they place a heavy burden on the servers.
* *maxIPCacheSize* to *shareOfRetainedFormerRequests*: These settings proved reliable and effective over several years of operation.

# Monitoring

After initial deployment, the valve should be monitored closely to detect and resolve any unintended disruption to legitimate users early on.

Blocked requests are recorded in the Tomcat log files and can be filtered using the keyword `AntiDoSMonitor`.

Alternatively, the valve can be monitored via JMX (e.g. using `JConsole` or VisualVM). Internal monitor metrics are exposed via JMX, and configuration parameters can even be adjusted at runtime without restarting the server.

Since version 1.6.0 the [Internal Status Dashboard](#internal-status-dashboard) adds an additional HTTP endpoint to monitor the valve. This can be used for monitoring the valve in a more convenient way.

# Marking Mode

Available since version 1.2.0, this mode enables use cases where the valve works cooperatively with web applications running on Tomcat. Instead of blocking requests outright, the valve's ability to detect suspicious traffic can provide hints to the application, allowing for gentler handling. In marking mode, the valve **never blocks** requests; it only attaches metadata to the `HttpServletRequest` for the application to inspect.

One example is preventing email address harvesting on public web pages: the application can check for the valve's flag and hide email addresses (or present a captcha / explanatory message) once request rates look suspicious, without outright blocking regular visitors. This also allows for tighter rate-limiting thresholds because the risk of disrupting normal users is much lower.

Example configuration:

        <Valve className="org.henbru.antidos.AntiDoSValve"
                monitorMode="marking"
                monitorName="MARKING-VALVE"
                alwaysAllowedIPs=""
                alwaysForbiddenIPs=""
                relevantPaths=".*/swa"
                maxIPCacheSize="50"
                numberOfSlots="10"
                slotLength="30"
                allowedRequestsPerSlot="5"
                shareOfRetainedFormerRequests="0"
        />

The following servlet demonstrates how to read the information provided by the valve:

		package org.henbru.antidos;
		
		import java.io.IOException;
		import java.io.PrintWriter;
		
		import jakarta.servlet.ServletException;
		import jakarta.servlet.annotation.WebServlet;
		import jakarta.servlet.http.HttpServlet;
		import jakarta.servlet.http.HttpServletRequest;
		import jakarta.servlet.http.HttpServletResponse;
		
		/**
		 * This servlet demonstrates the marking mode of the valve
		 * 
		 * @author henni
		 *
		 */
		@WebServlet(urlPatterns = "/swa")
		public class ServiceWAntiDoSValve extends HttpServlet {
		
			private static final long serialVersionUID = -7841500356151595460L;
		
			@Override
			protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
				
				PrintWriter answer = resp.getWriter();
				String antiDoSStatus = (String) req.getAttribute("org.henbru.antidos.AntiDoS");
				
				if (antiDoSStatus == null) {
					answer.print("AntiDoSStatus: OK");
				} else {
					answer.print("AntiDoSStatus: Suspicious! ");
					answer.print("Details: " + antiDoSStatus);
				}
				answer.close();
			}
		}

In marking mode, the valve sets the request attribute `"org.henbru.antidos.AntiDoS"` with a string containing the *monitorName*. Requests from IP addresses matching *alwaysForbiddenIPs* are always marked, but not blocked.

# Multi-Instance Configurations

In some scenarios, it can be useful to apply different rules to different parts of your application or different client IP ranges. While a single valve/monitor instance cannot do this alone, version 1.1 introduced support for running multiple valve instances concurrently.

The *monitorName* parameter is required to keep the configurations distinct. Blocking and marking valves can also be combined. Here is an example with two valve instances:

        <Valve className="org.henbru.antidos.AntiDoSValve"
                monitorName="TEST-VALVE"
                alwaysAllowedIPs=""
                alwaysForbiddenIPs=""
                relevantPaths="/valvetest"
                maxIPCacheSize="50"
                numberOfSlots="10"
                slotLength="30"
                allowedRequestsPerSlot="5"
                shareOfRetainedFormerRequests="0"
        />
        
        <Valve className="org.henbru.antidos.AntiDoSValve"
                monitorName="TEST-VALVE-2"
                alwaysAllowedIPs=""
                alwaysForbiddenIPs=""
                relevantPaths="/valvetest2"
                maxIPCacheSize="50"
                numberOfSlots="10"
                slotLength="30"
                allowedRequestsPerSlot="3"
                shareOfRetainedFormerRequests="0"
        />

The second valve only monitors requests to `/valvetest2` and applies a stricter limit. In the server logs, you will see separate messages from each valve instance.

Use cases for multi-instance configurations:

## Testing a new configuration

You can run a new configuration alongside the active one in simulation mode to evaluate how it behaves under real traffic. This keeps your server protected while you fine-tune the new rules before switching over.

## Allowing higher rate limits for trusted partner servers

If known partners need to access your service at higher rates than public users, you can use two valves:
1. The first valve enforces the standard (stricter) limit for general traffic. In *alwaysAllowedIPs*, you whitelist the trusted partner IPs so this valve ignores them.
2. The second valve defines the higher limit intended for those partners. While this limit technically applies to all traffic, public clients will have already been constrained by the first valve.

## Separate configuration for status interface and monitor valves

If you plan to use the dashboard feature in a multi-valve setup, it is strongly recommended to configure a **dedicated valve for the status interface and place it as the first valve in the pipeline** (`server.xml`).

**Why place the status valve first?**
* **Early Pipeline Interception:** Tomcat evaluates valves strictly in the order they are declared in `server.xml`. Placing the dedicated status valve first ensures requests to `statusUri` are intercepted and fulfilled immediately.
* **No Unintended Rate Limiting:** If `statusUri` were placed on a downstream valve, any preceding valve configured with general path patterns (e.g. `relevantPaths=".*"`) would treat dashboard requests as normal application traffic, counting them toward quota limits and potentially blocking administrators.
* **Fleet-Wide Visibility:** Because the status dashboard automatically discovers and aggregates metrics from all active valves in the Tomcat JVM, a single dedicated status valve placed at the top provides full observability without needing `statusUri` configured anywhere else.

Here is an example configuration:

    <Valve className="org.henbru.antidos.AntiDoSValve"
        monitorName="STATUS-VALVE"
        statusUri="/antidos-status"
        maxIPCacheSize="10"
        numberOfSlots="5"
        slotLength="10"
        allowedRequestsPerSlot="5"
        shareOfRetainedFormerRequests="0"
    />

    <Valve className="org.henbru.antidos.AntiDoSValve"
        monitorName="MARKING-VALVE"
        monitorMode="marking"
        relevantPaths=".*/swa"
        maxIPCacheSize="50"
        numberOfSlots="10"
        slotLength="30"
        allowedRequestsPerSlot="5"
    />

## Honeypot Probing Trap with Server-Wide Blocking

You can configure a dedicated Honeypot valve in `server.xml` positioned before your application valve. By combining `allowedRequestsPerSlot="0"` with `serverWideBlocking="true"` and path regexes matching non-existent technologies (`*.php`, `*.cgi`, `*.aspx`, `/wp-admin`, `/.env`), vulnerability scanners and hostile bots are blocked across the entire server upon their very first probing request:

    <Valve className="org.henbru.antidos.AntiDoSValve"
        monitorName="HONEYPOT-PROBE-VALVE"
        description="Zero-tolerance honeypot trap blocking probers across the entire server"
        relevantPaths=".*\.(php|cgi|aspx)$|.*/wp-.*|.*/\.env.*"
        allowedRequestsPerSlot="0"
        serverWideBlocking="true"
        maxIPCacheSize="500"
        maxBlockedIPCacheSize="1000"
        numberOfSlots="6"
        slotLength="300"
        shareOfRetainedFormerRequests="0"
        httpStatusCode="429"
    />


# Block Log Throttling

Under massive DDoS attacks with thousands of rejected requests per second, writing a log entry for every blocked request would quickly saturate disk I/O and create thread contention within the logging subsystem. To protect server stability, the valve incorporates an internal, lock-free log rate limiter that caps block messages at **20 logs per second** by default. Any surplus messages within that second are dropped, and an aggregated summary line (`Suppressed X block log events in the previous interval`) is logged at the start of the next second.

*Note:* Log throttling is designed as a built-in safety net and cannot currently be configured through XML attributes in `server.xml`. (Programmatic customization via `setMaxBlockLogsPerSecond(...)` is available in code for testing or custom integrations).

# Internal Status Dashboard

While the valve's runtime state can be monitored via JMX (e.g. using `JConsole` or VisualVM), in modern containerized and cloud environments (Docker, Kubernetes) JMX ports are often not exposed or require cumbersome port-forwarding and certificate management. To simplify operations, troubleshooting, and health checks, version 1.6.0 introduces an optional built-in **HTTP Status Dashboard**.

The dashboard provides an instant, unified overview of all AntiDoS valves active within the Tomcat JVM, their effective configurations, and real-time cache utilization metrics.

## Single Pane of Glass: Multi-Valve Aggregation

In servers running multiple valve instances (e.g., host-level rate limiting alongside application-specific rules), you only need to configure `statusUri` on **one** valve. When accessed, that valve automatically collects and displays information from all active valves in the server:

* **Valve Configuration:** Mode (`BLOCKING` / `MARKING`), HTTP status code, simulation mode, server-wide blocking, relevant and non-relevant path patterns.
* **Rate Limiting Parameters:** Request limits, slot lengths, retention factor, active slots count.
* **Subnet Aggregation:** Configured IPv4 and IPv6 subnet aggregation masks.
* **Cache & Memory Utilization:** Current count of tracked IP counters vs. configured cache caps, currently blocked IPs, and total lifetime request counts.

### Recommendation for Multi-Valve Setups

* **Configure `statusUri` only on the first valve (or a dedicated status valve):** Always configure `statusUri` on the **first valve in the pipeline** in `server.xml`, or create a dedicated status valve placed before all application valves. Because Tomcat processes valves sequentially, this ensures dashboard requests are answered directly at the entrance of the valve chain and are never subject to the path filters, request counting, or quota limits of other valves.
* **Avoid multiple different `statusUri` configurations:** Configuring different status URIs across multiple valves creates redundant endpoints with separate passwords/tokens. Moreover, upstream valves would interpret requests to downstream status endpoints as regular application traffic unless explicitly excluded via `nonRelevantPaths`.

## Lightweight, Self-Contained Design

The status dashboard is engineered for high performance and zero external footprint:
* **No External Dependencies:** No external stylesheets, fonts, or JavaScript libraries (100% self-contained).
* **Dark & Light Mode:** Built-in theme switcher with client-side persistence and anti-FOUC initialization, retaining a clean terminal aesthetic across both palettes without external assets.
* **Minimal Payload:** Compact HTML (< 4 KB) styled with system monospaced fonts (`ui-monospace`, `Menlo`, `Consolas`) for a clean terminal/dashboard look.
* **Zero Reflection / Low Overhead:** Generated directly via an internal `StringBuilder` without template engines.
* **JSON API:** Appending `?format=json` or sending an `Accept: application/json` header returns a machine-readable JSON representation, ideal for automated health checks, uptime monitoring, or Prometheus scrapers.

## Security Considerations & Defense Mechanisms

Exposing internal rate-limiting metrics over HTTP presents security risks (such as reconnaissance or brute-force attempts). The dashboard incorporates multiple layers of defense to remain safe by default:

1. **Secure by Default:**
   The dashboard is **completely disabled** unless `statusUri` is explicitly set in `server.xml`.
2. **Auto-Generated Cryptographic Random Password:**
   If `statusPassword` is left empty or omitted, the valve automatically generates a cryptographically secure random token (16–20 characters) using `SecureRandom` and prints it to the server logs on startup.
   * **Console-Friendly HEX Alphabet (`0-9a-f`):** The token uses exclusively lowercase hexadecimal characters without symbols or ambiguous characters (`0`/`O`, `1`/`l`). This allows quick double-click selection and copy-pasting from terminal logs without shell-escaping issues in `curl`.
   * **Confidentiality in Logs:** If a custom password is configured in `server.xml`, it is **never** printed to the server logs to prevent leaking credentials into central log aggregators. Only auto-generated tokens are logged on startup.
   * **JVM-Wide Token:** The auto-generated token is shared across all valves in the JVM, ensuring consistent authentication across multi-valve deployments.
3. **Protection Against Brute-Force via Asymmetric Rate Limiting:**
   Authentication attempts against the status endpoint are protected by the valve's own DoS rate limiter:
   * **Legitimate Requests:** Successfully authenticated requests with the correct token are **not** counted against rate limits, ensuring administrators do not lock themselves out while refreshing the dashboard.
   * **Failed Attempts:** Any request with a missing or incorrect password is immediately registered as a request in the valve's monitor. If an attacker repeatedly guesses passwords, their IP address exceeds the allowed threshold and is automatically blocked (`HTTP 429 Too Many Requests`).
   * **Pre-Check Block for Unauthorized Requests:** If an IP is already blocked for DoS violations and attempts to query the status endpoint without the correct token, it is immediately rejected with HTTP 429 without performing password verification or consuming monitor resources. Valid authentication with the admin token, however, is always honored so administrators can inspect the valve even from a temporarily blocked IP.
4. **IP Whitelisting (`statusAllowedIPs`):**
   Access can be restricted to internal management subnets or localhost using a regular expression (e.g. `statusAllowedIPs="127\.0\.0\.1|::1|10\..*"`). Requests from unauthorized IPs receive `404 Not Found` to conceal the endpoint's existence.
5. **Constant-Time Token Comparison:**
   Passwords are verified using `MessageDigest.isEqual(...)` to prevent timing-based side-channel attacks.

## Configuration Options

| Attribute | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `statusUri` | No | *(disabled)* | The URI path at which the dashboard is served (e.g. `/antidos-status`). If empty or omitted, the endpoint is disabled. |
| `statusAllowedIPs` | No | *(all IPs allowed)* | Regular expression matching client IPs permitted to query the dashboard. Unauthorized IPs receive `404 Not Found`. |
| `statusPassword` | No | *(auto-generated)* | Access password. If specified, must be at least 10 characters long. If omitted, a random 16–20 character HEX token is generated and printed to the console on startup. |

## Configuration Example

```xml
<Valve className="org.henbru.antidos.AntiDoSValve"
       monitorName="STATUS-VALVE"
       statusUri="/antidos-status"
       statusAllowedIPs="127\.0\.0\.1|::1|10\..*"
       statusPassword=""
       allowedRequestsPerSlot="10"
       slotLength="10"
       numberOfSlots="1"
       maxIPCacheSize="50" />
```

## Accessing the Dashboard

* **In the browser (Dashboard):**
  `http://localhost:8080/antidos-status?token=<token>`
* **Interactive API Documentation (OpenAPI 3.1 & REST Guide):**
  `http://localhost:8080/antidos-status?token=<token>&view=docs`
* **OpenAPI 3.1 Machine-Readable JSON Specification:**
  `curl -H "Authorization: Bearer <token>" "http://localhost:8080/antidos-status?format=openapi"`
* **Via Bearer Authorization:**
  `curl -H "Authorization: Bearer <token>" http://localhost:8080/antidos-status`
* **JSON Overview (All Valves):**
  `curl -H "Authorization: Bearer <token>" "http://localhost:8080/antidos-status?format=json"`
* **JSON Details (Current Slot):**
  `curl -H "Authorization: Bearer <token>" "http://localhost:8080/antidos-status?view=details&format=json&valve=STATUS+VALVE"`
* **JSON Details (Last Completed Slot & All Blocked IPs):**
  `curl -H "Authorization: Bearer <token>" "http://localhost:8080/antidos-status?view=details&format=json&valve=STATUS+VALVE&slot=previous&blockedLimit=all&activeLimit=0"`
* **Filter Specific Valve (HTML View):**
  `http://localhost:8080/antidos-status?token=<token>&valve=STATUS+VALVE`

> [!TIP]
> The static OpenAPI 3.1 specification is also available in the repository at [docs/openapi.yaml](docs/openapi.yaml) and [docs/openapi.json](docs/openapi.json) for easy integration into SIEM tools, Postman, or client SDK generators.

## Monitoring Collector Parameters

When polling the status endpoint from automated monitoring scripts, SIEM systems, or collectors:

| Parameter | Values | Description |
|---|---|---|
| `format` | `json`, `openapi` | Renders machine-readable output: `json` for monitor metrics or `openapi` (or `openapi.json`) for the full OpenAPI 3.1 specification. Also negotiated via `Accept: application/json` or `Accept: application/vnd.oai.openapi+json`. |
| `view` | `details`, `docs`, `openapi` | Selects the response view: `details` for deep slot/counter forensics, `docs` (or `api`) for interactive HTML API documentation in dashboard style, or `openapi` for OpenAPI JSON. |
| `slot` | `current`, `previous`, `<slotKey>` | Selects which slot's blocked/active client list to inspect. Using `slot=previous` returns the completed previous time window (requires `numberOfSlots >= 2`; collectors should deduplicate by `slotKey`). Default: `current`. |
| `limit` | positive integer (e.g. `100`), `all`, `-1` | Maximum number of clients returned (applies to both blocked and active lists as fallback). `all` or `-1` returns all entries (HTML tables capped at 1,000 for browser responsiveness). `0` or omitted defaults to `50`. |
| `blockedLimit` | positive integer, `0`, `all`, `-1` | Specific limit for the `blockedClients` list. Falls back to `limit` if omitted. Specifying `0` suppresses blocked clients entirely. |
| `activeLimit` | positive integer, `0`, `all`, `-1` | Specific limit for the `topActiveClients` list. Falls back to `limit` if omitted. Specifying `0` suppresses active clients entirely. |
| `sinceBlockedOrder` | monotonic timestamp/sequence (`long`) | Delta filter for `blockedClients`. When present, **takes precedence over `blockedLimit`/`limit`**, disabling heap sorting and returning only entries updated after this sequence number ($O(N)$ linear filter). The limit parameters can still be passed in the same request as a backward-compatible fallback for older Valves. Response includes `maxBlockedOrder` as the cursor watermark for subsequent polls. |
| `sinceActiveOrder` | monotonic timestamp/sequence (`long`) | Delta filter for `topActiveClients`. When present, **takes precedence over `activeLimit`/`limit`**, disabling heap sorting and returning only entries updated after this sequence number ($O(N)$ linear filter). The limit parameters can still be passed in the same request as a backward-compatible fallback for older Valves. Response includes `maxActiveOrder` as the cursor watermark for subsequent polls. |
| `activeMinCount` | positive integer (e.g. `2`) | Minimum request count filter for `topActiveClients`. Suppresses low-frequency single-request visitors to keep payloads lightweight under heavy traffic. Default: `1` (all active clients). |
| `valve` | `<monitorName>` | Filters by monitor name (required for details view if multiple valves are running). |

---

# Anti-DoS Collector & Fleet Management

For multi-server fleet monitoring, threat intelligence, and advanced analytics across multiple Tomcat nodes, check out the standalone **[Anti-DoS Collector](collector/README.md)**:
* **[Fleet Architecture & Dual-Plane Guide](collector/README.md)**: Deep dive into the synergy between edge Tomcat Valves and central Collector intelligence.
* Real-time HTMX fleet dashboard with Incident Explorer, 2D Residential Proxy Scatterplots, Subnet/ASN Rollup, and Bot categorization.
* Built-in Demo Mode (`java -jar anti-dos-collector-*.jar demo`) for instant exploration.
* **[Production Setup & Operations Guide](collector/SETUP_GUIDE.md)** for configuring automated 24/7 systemd operation with conflict-free GitHub updates.
* **[Relational Database Schema & Data Model](collector/SETUP_GUIDE.md#relational-database-schema--data-model)** describing all tables, attributes, entity relationships, and indexing strategies.



