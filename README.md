# What is the Anti-DoS Valve?

This project implements a Tomcat valve that enforces dynamic access rate limits on requests from individual IP addresses or subnets. This helps prevent Tomcat servers from becoming overloaded by DoS attacks or aggressive web crawlers, or at least mitigates their impact.

The valve cannot, of course, provide complete protection against every kind of malicious overload. The goal is rather to provide a simple, easy-to-use overload protection mechanism that can be deployed quickly and with minimal effort, introduces very little overhead in Tomcat, and is particularly effective at slowing down aggressive web crawlers.

The valve is highly configurable and also provides options to permanently block specific IP addresses or subnets, or to exclude trusted IP addresses and subnets from blocking altogether.

A key goal during development was comprehensive unit test coverage to ensure the correct functioning of this code at a central point in the Tomcat server.

A simulation tool is also provided as a Google Sheet. Additionally, the valve's status can be monitored and its configuration adjusted at runtime via JMX.

A Dockerfile is included to run Tomcat with the valve using minimal setup.

# Supported Tomcat Versions

Since version 1.4, the valve is built against Tomcat 10.1 libraries. This means it makes use of the <strong>jakarta.servlet.\*</strong> packages. Versions prior to 1.3.0 of the valve were tested on Tomcat 7.0, 8.0, and 9.0, using the legacy <strong>javax.servlet.\*</strong> packages.

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

1. Clone the project from GitHub and build the JAR with Maven: `mvn package` (or `mvn install`)
2. Make the JAR available in Tomcat. For example, copy it into `<CATALINA_HOME>/lib/` (probably alongside your JDBC drivers).
3. In `server.xml`, configure the valve inside the appropriate `<Host>` element (see example below).
4. Ensure logging is enabled so that blocked requests are logged (this is already enabled in the default configuration).

The valve is now active!

You can test its functionality using a non-existent URL to avoid impacting real applications. For testing, configure very low thresholds and trigger rapid reloads in your browser until the valve blocks your requests. The following sample configuration can be used for such a test:

        <Valve className="org.henbru.antidos.AntiDoSValve"
                monitorName="TEST VALVE"
                alwaysAllowedIPs=""
                alwaysForbiddenIPs=""
                relevantPaths="/valvetest"
                nonRelevantPaths=""
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

Once you have identified these values, you can craft your valve configuration using the parameters described below.

## Interactive Configuration Helper & Traffic Simulator

To simplify sizing, tuning, and understanding the valve's behavior, the repository includes a self-contained, browser-based tool: [**anti-dos-valve-config-helper.html**](https://github.com/ihbrune/Anti-DoS-Valve/blob/master/anti-dos-valve-config-helper.html) (open it directly in your web browser without requiring a server or external dependencies).

It provides:
* **Interactive XML Generator & Presets:** Choose from presets (e.g. Production Standard, Aggressive Bot Defense, or Marking Mode), customize parameters, and generate ready-to-use Tomcat `server.xml` snippets with live validation and cache mode diagnostics (Sync LRU vs. Async Batch).
* **Single-Client Simulation:** Deep-dive into how the rolling slot window, lookback retention (`shareOfRetainedFormerRequests`), permitted burst capacity before the first block, and sustainable continuous rates affect an individual visitor or attacker over 49 consecutive time slots.
* **Fleet & DDoS Multi-IP Simulation:** Model high-concurrency traffic from hundreds or thousands of simultaneous clients and botnets. It evaluates memory pressure in real time, visualizes Active and Blocked Cache fill levels against safety thresholds (including the 90% low-watermark eviction trigger and 120% circuit-breaker hard-cap), and highlights security risks such as unblocking leaks when the blocked cache overflows.

## Request Evaluation Pipeline

When an incoming HTTP request reaches the valve, it is evaluated sequentially through the following decision pipeline:

1. **Static Blacklist (`alwaysForbiddenIPs`)**: Does the client IP address match the regular expression pattern? &rarr; **Block (HTTP error code)**.  
   *(Evaluated directly on the individual client IP address string; request is not counted in the dynamic rate monitor).*
2. **Static Whitelist (`alwaysAllowedIPs`)**: Does the client IP address match the regular expression pattern? &rarr; **Allow**.  
   *(Evaluated directly on the individual client IP address string; request is not counted in the dynamic rate monitor).*
3. **Path Whitelist (`nonRelevantPaths`)**: Does the request URI match `nonRelevantPaths`? &rarr; **Allow**.  
   *(Request is not counted; bypasses rate limiting for health-checks, status endpoints, or static error pages even if the client IP or its subnet is currently blocked).*
4. **Detector Match (`relevantPaths`)**: Does the request URI match `relevantPaths`?
   * **Yes**: The client IP is resolved to a counter key — either the **individual IP address** or the **aggregated CIDR subnet** (if `ipv4SubnetMask` or `ipv6SubnetMask` is configured). The request is registered and counted in the rate limiting monitor. If the threshold for this counter key is exceeded (or already locked) &rarr; **Block**; otherwise &rarr; **Allow**.
5. **Server-Wide Enforcement (`serverWideBlocking`)**: If the URI does *not* match `relevantPaths`, but `serverWideBlocking="true"` is enabled:
   * Is the client IP address (or its aggregated subnet) currently blocked by the monitor? &rarr; **Block** (read-only check; the request is not counted and creates no cache entries).
6. **Default / Unmonitored**: If the URI does *not* match `relevantPaths` and the client IP address (or its subnet) is not blocked &rarr; **Allow** (neither counted nor blocked).

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

## alwaysForbiddenIPs

An optional regular expression defining IP addresses that are always blocked. This option (and `alwaysAllowedIPs`) operates independently of the dynamic rate limiter: matched IPs are unconditionally blocked or allowed.

*Tip:* You can use [RegexPlanet](http://www.regexplanet.com/advanced/java/index.html) to test Java regular expressions.

*Tip 2:* If you only need this static blocking feature, you can use Tomcat's built-in [Remote Address Valve](https://tomcat.apache.org/tomcat-10.0-doc/config/valve.html#Remote_Address_Valve).

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

## nonRelevantPaths

Available since version 1.4.0 and evaluated before *relevantPaths*: allows specific URL paths to be excluded from monitoring so they are never rate-limited.

This is especially helpful when an entire path hierarchy should be protected, except for a few specific endpoints. For example:

* `relevantPaths="/myexampleapi/.*"` protects all API endpoints.
* `nonRelevantPaths="/myexampleapi/status"` keeps only the health/status endpoint accessible without rate limiting. Without `nonRelevantPaths`, you would have to enumerate every other endpoint individually in `relevantPaths`, and remember to update it whenever a new endpoint is deployed. With `nonRelevantPaths`, newly added endpoints are protected automatically.

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

*Note:* Whitelisted IP addresses configured in *alwaysAllowedIPs* (e.g. `127.0.0.1` or specific internal machines) are evaluated prior to rate limiting and subnet aggregation, so individual whitelisted IPs remain accessible even if their subnet would otherwise be blocked.

## ipv6SubnetMask (optional)

Configures subnet aggregation for IPv6 addresses. In IPv6 networks, attackers often have access to vast address pools (e.g. entire `/64` subnets) and can generate virtually unlimited unique IP addresses to easily bypass per-IP rate limits and flush cache entries.

When set to a prefix length smaller than 128 (e.g. `64` for `/64`), all IPv6 addresses within that prefix share the same rate-limiting counter (e.g. `2001:db8:abcd:12::/64`).

Accepts:
* Prefix length integer (1 to 128), e.g. `64` or `48`
* CIDR notation string, e.g. `"/64"`
* `128` or `-1`: Disables IPv6 aggregation (default behavior).

## slotLength

The duration of a slot in seconds (must be an integer greater than 0). The slot length and *allowedRequestsPerSlot* are closely related:

## allowedRequestsPerSlot

The maximum number of requests permitted within a slot before an IP address or subnet is blocked (must be an integer greater than 0). As described above, the check evaluates the sum of requests in the current slot plus requests carried over from previous slots.

Increasing *slotLength* should typically be paired with an increase in *allowedRequestsPerSlot* to avoid blocking legitimate users. However, higher limits also give attackers more leeway before a block triggers.

Conversely, setting *slotLength* too low diminishes the advantages of slot-based tracking, as more slots must be maintained and evaluated.

## numberOfSlots

The number of slots the monitor maintains in memory (must be an integer greater than 0). With a value of 1, the monitor retains no memory beyond the active slot. Larger values give the monitor a longer historical 'memory'.

This history is used when requests from earlier slots are factored into evaluating an IP address in the current slot (see *shareOfRetainedFormerRequests*).

## shareOfRetainedFormerRequests

Defines the degree to which past requests from an IP address or subnet influence its evaluation in the current slot (must be a floating-point value greater than or equal to 0). The monitor calculates the average request count across previous slots and multiplies it by this factor. A higher value penalizes an IP address longer for past traffic spikes, whereas a low value allows a previously blocked IP to make requests again soon after a new slot begins. Example values:

* `0`: No historical request counts are carried over. In this case, *numberOfSlots* should be set to 1 to minimize memory usage.
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

# Sample Configurations

The configuration shown above can serve as a starting point for your production setup.

You can test the effects of configuration values in the 'Traffic & Attack Simulator' section of [**anti-dos-valve-config-helper.html**](https://github.com/ihbrune/Anti-DoS-Valve/blob/master/anti-dos-valve-config-helper.html), or copy this entire [**Google Sheet**](https://docs.google.com/spreadsheets/d/1eztKVnzjW9xVVia1hDAeLaiiKRAGfNKRFx5lvKkbLBs/edit?usp=sharing) to your own Google account and adjust the fields marked **'set me!'** to see how different parameters affect request thresholds for attackers and regular users.

Finally, define your *relevantPaths* pattern. Ideally, this should cover only endpoints that are publicly accessible and consume noticeable server resources. Here is a real-world example:

        <Valve className="org.henbru.antidos.AntiDoSValve"
                monitorName="MY VALVE"
                alwaysAllowedIPs="10\.68\.\d+\.\d+|10\.77\.\d+\.\d+"
                alwaysForbiddenIPs=""
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

# Marking Mode

Available since version 1.2.0, this mode enables use cases where the valve works cooperatively with web applications running on Tomcat. Instead of blocking requests outright, the valve's ability to detect suspicious traffic can provide hints to the application, allowing for gentler handling. In marking mode, the valve **never blocks** requests; it only attaches metadata to the `HttpServletRequest` for the application to inspect.

One example is preventing email address harvesting on public web pages: the application can check for the valve's flag and hide email addresses (or present a captcha / explanatory message) once request rates look suspicious, without outright blocking regular visitors. This also allows for tighter rate-limiting thresholds because the risk of disrupting normal users is much lower.

Example configuration:

        <Valve className="org.henbru.antidos.AntiDoSValve"
                monitorMode="marking"
                monitorName="MARKING VALVE"
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
                monitorName="TEST VALVE"
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
                monitorName="TEST VALVE 2"
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

*Testing a new configuration:*

You can run a new configuration alongside the active one in simulation mode to evaluate how it behaves under real traffic. This keeps your server protected while you fine-tune the new rules before switching over.

*Allowing higher rate limits for trusted partner servers:*

If known partners need to access your service at higher rates than public users, you can use two valves:
1. The first valve enforces the standard (stricter) limit for general traffic. In *alwaysAllowedIPs*, you whitelist the trusted partner IPs so this valve ignores them.
2. The second valve defines the higher limit intended for those partners. While this limit technically applies to all traffic, public clients will have already been constrained by the first valve.

# Block Log Throttling

Under massive DDoS attacks with thousands of rejected requests per second, writing a log entry for every blocked request would quickly saturate disk I/O and create thread contention within the logging subsystem. To protect server stability, the valve incorporates an internal, lock-free log rate limiter that caps block messages at **20 logs per second** by default. Any surplus messages within that second are dropped, and an aggregated summary line (`Suppressed X block log events in the previous interval`) is logged at the start of the next second.

*Note:* Log throttling is designed as a built-in safety net and cannot currently be configured through XML attributes in `server.xml`. (Programmatic customization via `setMaxBlockLogsPerSecond(...)` is available in code for testing or custom integrations).

