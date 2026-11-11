# Release Notes – Version 1.9.0

Version 1.9.0 introduces **Active Fleet Mitigation and Dynamic CIDR Subnet Blocking**, completing the strategic transition from passive telemetry and forensics to an autonomous, closed-loop defense network. It establishes secure, bidirectional communication between the central **Anti-DoS Collector** and edge **Anti-DoS Valve** instances, allowing operators and automated heuristic engines to enforce, extend, and revoke temporary, TTL-based subnet blocks across the entire server fleet at runtime without restarting Apache Tomcat.

Additionally, Version 1.9.0 delivers major analytical and operational enhancements: full-spectrum **User-Agent bot profiling**, an **ASN Drilldown Analysis Modal**, **Carpet Attack Radar**, emergency fleet flush capabilities, **asynchronous Slack and Webhook alerting**, native private IP auto-allowlist support in the Valve, and robust resource concurrency safeguards.

---

## Highlights

### 🛡️ Closed-Loop Active Fleet Mitigation *(Valve & Collector)*
Until now, mitigation of coordinated attacks (such as residential proxy scraper swarms or cloud botnets) required either adjusting rate-limiting thresholds or manually updating static regular expressions in Tomcat's `server.xml` and restarting the server. Version 1.9.0 introduces dynamic, non-disruptive runtime blocking:

- **Dynamic CIDR Mitigation API:** Tomcat Valves accept authenticated runtime mitigation commands via HTTP `POST` to dynamically block arbitrary IPv4 or IPv6 CIDR subnets (e.g., `198.51.100.0/24` or `2001:db8:abcd::/48`) or individual IP addresses.
- **Dedicated Configuration & Strict Isolation:**
  - `mitigationPassword`: Secret token (minimum 10 characters) activating the dynamic mitigation endpoint on that Valve.
  - `mitigationUri`: Dedicated write URI path (optional, falls back to `statusUri`).
  - `mitigationAllowedIPs`: IP filter restricting mitigation commands exclusively to trusted IPs (e.g. the central Collector) while allowing wider access on `statusAllowedIPs`.
  - Dynamic blocks are strictly isolated to the Valve instance where `mitigationPassword` is configured (no JVM-wide leakage), allowing upstream monitoring or simulation Valves in the same pipeline to continue observing raw traffic baselines.
- **Fail-Safe Valve Guardrails:**
  - `alwaysAllowedIPs` Precedence: Whitelisted client IPs and intranet ranges always take precedence and can never be locked out by a dynamic subnet block.
  - Prefix Width Guardrails (`mitigationMinPrefixV4`, `mitigationMinPrefixV6`): Prevents dangerous collateral damage by rejecting overly broad supernet blocks (e.g. `/8` or `/12`) with `HTTP 400 Bad Request`.
  - Bounded Self-Expiring TTL (`mitigationMaxTtlSeconds`, default 24h): Every dynamic block carries a mandatory expiration timestamp. Rules expire automatically in-memory even if the Collector becomes completely unreachable.
  - Capacity Protection (`mitigationMaxActiveBlocks`, default 5,000): Atomic rejection with `HTTP 409 Conflict` prevents memory exhaustion and bounds blast radius.
- **Dynamic Rules Hash Versioning & Circuit Breaker:** Valves calculate a compact version hash of their active dynamic ruleset. The Collector verifies hash parity during scheduled polling cycles to eliminate redundant network sync payloads, and engages a circuit breaker to halt rule pushes if a Valve becomes unstable or desynchronized.
- **Emergency Fleet Flush:** A dedicated kill-switch in the Mitigation Cockpit allows operators to immediately revoke and flush all active dynamic mitigation rules across the entire fleet in one atomic action during false-positive emergencies.
- **Attacker Deterrence Tracking:** When traffic matches an active dynamic block, the Valve responds with `HTTP 429 Too Many Requests` (or configured status code) and records synthetic deterrence counters (`CIDR:<subnet>`). Telemetry captures blocked request volume, distinct client IP cardinality, distinct User-Agents, and forensic sample request snapshots (`method`, `uri`, `userAgent`, and `sampleAuthenticated`). The Collector aggregates these deterrence metrics into behavioral states: `OBSERVING`, `PERSISTENT`, and `DETERRED`.

### 🤖 Autonomous Defense Engine & Carpet Radar *(Collector)*
For hands-off protection during off-hours, the Collector features an autonomous threat mitigation engine:

- **Continuous Telemetry Evaluation:** Evaluates live traffic patterns on scheduled 2-minute cycles to detect volumetric attack waves, high-surge subnets, and rotating residential proxy botnets.
- **Carpet Attack Radar:** Detects horizontal scanning waves scattered across multiple `/24` subnets belonging to a single Autonomous System, proactively suggesting or triggering subnet mitigations before individual nodes are overloaded.
- **Configurable Scope & Operating Windows:**
  - *Protected ASNs:* Whitelist critical transit providers, payment gateways, or corporate networks to ensure they are unconditionally exempt from autonomous blocking.
  - *Operating Window Hours:* Restrict auto-mitigation actions to high-risk off-peak/night hours, or run continuously 24/7.
- **7 Deterministic Safety Guardrails:**
  1. *Hard Whitelist Immunity:* Verified search engine crawlers (Googlebot, Bingbot, Applebot), internal private networks (RFC 1918), and loopback addresses are unconditionally protected from auto-mitigation.
  2. *Prefix Constraints:* Blocks cannot exceed configured subnet bounds (e.g. minimum `/24` for IPv4).
  3. *Rate-of-Fire / Blast Radius Limits:* Limits the maximum number of automated mitigations created per hour across the fleet to prevent cascade misconfigurations.
  4. *Strict Maximum TTL:* Caps autonomous blocks to a safe duration (e.g., 2 to 6 hours).
  5. *Cooldown Intervals:* Prevents rule thrashing by enforcing a mandatory cooldown period before a previously mitigated subnet can be automatically targeted again.
  6. *Human Override Immunity:* Manually created or extended mitigation rules are tagged as operator-enforced and are never overridden or prematurely expired by the automated engine.
  7. *Runtime Dominance (`system_settings`):* Settings follow a strict **Database-over-File** hierarchy. Operations teams can enable, tune, or instantly disable autonomous mitigation via the Web UI without editing YAML files or restarting the Collector service.

### 🕵️ User-Agent Analytics & Bot Profiling (`tab=user-agents`) *(Collector)*
The **User-Agents** focus tab cross-correlates request header samples captured by Anti-DoS Valves with Autonomous Systems and rate-limiting incidents across the fleet:

- **Semantic Family Categorization:** Classifies User-Agent strings into structured client families without external dependencies:
  - *Browsers:* `CHROME`, `FIREFOX`, `SAFARI`, `EDGE`, `OPERA`, `MOBILE_BROWSER`.
  - *Automated Tools & Libraries:* `PYTHON_REQUESTS`, `CURL`, `GO_HTTP`, `JAVA_HTTP`, `NODE_FETCH`, `PHP_HTTP`, `SCRAPY`, `POSTMAN`, `AUTOMATED_TOOL`.
  - *Crawlers & Spiders:* `SEARCH_CRAWLER`, `AI_CRAWLER`.
  - *Anomalous / Missing:* `EMPTY_OR_BLANK`, `CUSTOM_OR_UNKNOWN`.
- **Authenticated Client Share (`sampleAuthenticated`):** Tracks whether a User-Agent was observed in requests carrying valid authenticated sessions. Legitimate browsers exhibit high authentication ratios, whereas scrapers rarely possess authenticated credentials.
- **Incident Rate Correlation:** Quantifies the proportion of samples associated with HTTP 429 rate blocks or simulation marks:
  $$\text{Incident Rate} = \frac{\text{Blocked Samples} + \text{Marked Samples}}{\text{Total Samples}} \times 100\%$$
- **Heuristic Suspicion Badges:**
  - 🔴 `SUSPICIOUS`: Assigned to scraping libraries, headless tools, or User-Agents exhibiting high incident rates combined with cloud hosting/datacenter infrastructure.
  - 🟢 `LEGITIMATE`: Browsers exhibiting confirmed authenticated logins and low incident rates across consumer/residential ASNs.
  - ⚪ `NEUTRAL`: Unclassified or moderate incident rates with mixed traffic.
- **Dedicated REST API:** Programmatic access via `/api/v1/analytics/user-agents`.

### 🔬 ASN Drilldown Analysis Modal *(Collector)*
An interactive forensic modal providing deep drilldowns into any Autonomous System observed across the fleet:
- 24-hour hourly traffic timeline comparing active vs. blocked requests.
- Subnet distribution table with direct 1-click mitigation shortcuts.
- User-Agent breakdown specific to that ASN, detailing incident rates, authentication ratios, and sample URIs.

### 🛡️ Valve Reliability, Security & Infrastructure Hardening *(Valve)*
- **`alwaysAllowPrivateIPs` (Valve):** Automatically allows private and local IP addresses without complex regexes (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback `127.0.0.0/8` and `::1`, link-local `169.254.0.0/16` and `fe80::/10`, IPv6 ULA `fc00::/7`).
- **`statusConcurrencyTimeoutMs` (Valve):** Protects Tomcat server threads and CPU resources during high-traffic incidents by limiting concurrent status requests (returns `HTTP 503 Service Unavailable` if concurrency queue capacity is exhausted).
- **`sampleAuthenticated` Tracking (Valve & Collector):** Request sample snapshots now record whether the request carried a verified authenticated session at the moment of sampling.
- **OpenAPI 3.1 Specification Updates:** Updated schema definitions covering dynamic mitigation commands, status concurrency timeouts, and sample authentication fields.

### 🔔 Comprehensive Multi-Channel Notifications *(Collector)*
- **Asynchronous Webhook & Slack Alerting:** The `AlertNotificationService` pushes structured alert cards to Slack incoming webhooks or generic JSON webhooks upon auto-mitigation events, complete with background thread dispatch and automatic retry logic.
- **Native Browser Desktop Notifications:** Optional opt-in to system desktop notifications via the Web Notifications API.
- **In-App Toast Alerts:** Real-time visual toasts in the Collector interface for auto-mitigation actions.
- **Alert Feed API:** Dedicated `/api/v1/mitigation/alerts` endpoint for polling and external SIEM integrations.

### 📊 Operational Reporting, Audit Logs & Diagnostic Polling *(Collector)*
- **Daily Reports with Mitigation Summary:** Daily operational reports now include a dedicated Autonomous Defense section documenting total dynamic rules created, manual vs. automated actions, and top mitigated ASNs.
- **Historical Rules & Audit Log Pagination:** Full search filtering and pagination across hundreds of past mitigation rules and audit trail records.
- **Diagnostic Polling Telemetry:** Poll Event Logs now record exact payload byte sizes and server-side JSON generation durations (ms) for every poll cycle to monitor network overhead.
- **Database Migrations (V25–V30):** Versioned schema migrations for dynamic mitigation rules, audit logs, valve guardrail metadata, system settings, poll log diagnostics, rules hash versioning, and sample authentication flags.

---

## Upgrading

### Valve
Upgrading the Valve from 1.8.0 is fully backwards-compatible:
1. Replace `anti-dos-valve-1.8.0.jar` with `anti-dos-valve-1.9.0.jar` (or `anti-dos-valve-1.9.0-tomcat9.jar` for Tomcat 9).
2. Existing configurations continue to function identically. Dynamic CIDR mitigation is dormant and disabled by default until `mitigationPassword` is explicitly set in `server.xml`.
3. If desired, configure `alwaysAllowPrivateIPs="true"` and `statusConcurrencyTimeoutMs="1000"` to leverage the new native intranet bypass and status concurrency safeguards.

### Collector
1. Replace `anti-dos-collector-1.8.0.jar` with `anti-dos-collector-1.9.0.jar`.
2. Database migrations (V25 through V30) execute automatically upon startup on both SQLite and PostgreSQL backends.
3. To enable the Collector to push dynamic mitigations to Valves, add `mitigation-token` or endpoint credentials to `collector-config.yaml` as described in [`collector/SETUP_GUIDE.md`](../collector/SETUP_GUIDE.md).
4. Review Autonomous Defense settings and Slack/Webhook alert URLs under `/mitigation` or in `collector-config.yaml`.
