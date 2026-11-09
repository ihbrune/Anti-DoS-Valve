# Release Notes – Version 1.9.0

Version 1.9.0 introduces **Active Fleet Mitigation and Dynamic CIDR Subnet Blocking**, completing the strategic transition from passive telemetry and forensics to an autonomous, closed-loop defense network. It establishes secure, bidirectional communication between the central **Anti-DoS Collector** and edge **Anti-DoS Valve** instances, allowing operators and automated heuristic engines to enforce, extend, and revoke temporary, TTL-based subnet blocks across the entire server fleet at runtime without restarting Apache Tomcat.

---

## Highlights

### 🛡️ Closed-Loop Active Fleet Mitigation *(Valve & Collector)*
Until now, mitigation of coordinated attacks (such as residential proxy scraper swarms or cloud botnets) required either adjusting rate-limiting thresholds or manually updating static regular expressions in Tomcat's `server.xml` and restarting the server. Version 1.9.0 introduces dynamic, non-disruptive runtime blocking:

- **Dynamic CIDR Mitigation API:** Tomcat Valves can now accept authenticated runtime mitigation commands via HTTP `POST` to dynamically block arbitrary IPv4 or IPv6 CIDR subnets (e.g., `198.51.100.0/24` or `2001:db8:abcd::/48`) or individual IP addresses.
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
- **Attacker Deterrence Tracking:** When traffic matches an active dynamic block, the Valve responds with `HTTP 429 Too Many Requests` (or configured status code) and records synthetic deterrence counters (`CIDR:<subnet>`). Telemetry captures blocked request volume, distinct client IP cardinality, distinct User-Agents, and forensic sample request snapshots (`method`, `uri`, `userAgent`). The Collector aggregates these deterrence metrics into behavioral states: `OBSERVING`, `PERSISTENT`, and `DETERRED`.

### 🤖 Autonomous Defense Engine (Auto-Mitigation) *(Collector)*
For hands-off protection during off-hours, the Collector now features an autonomous threat mitigation engine:

- **Continuous Telemetry Evaluation:** Evaluates live traffic patterns on scheduled 2-minute cycles to detect volumetric attack waves, high-surge subnets, and rotating residential proxy botnets.
- **7 Deterministic Safety Guardrails:**
  1. *Hard Whitelist Immunity:* Verified search engine crawlers (Googlebot, Bingbot, Applebot), internal private networks (RFC 1918), and loopback addresses are unconditionally protected from auto-mitigation.
  2. *Prefix Constraints:* Blocks cannot exceed configured subnet bounds (e.g. minimum `/24` for IPv4).
  3. *Rate-of-Fire / Blast Radius Limits:* Limits the maximum number of automated mitigations created per hour across the fleet to prevent cascade misconfigurations.
  4. *Strict Maximum TTL:* Caps autonomous blocks to a safe duration (e.g., 2 to 6 hours).
  5. *Cooldown Intervals:* Prevents rule thrashing by enforcing a mandatory cooldown period before a previously mitigated subnet can be automatically targeted again.
  6. *Human Override Immunity:* Manually created or extended mitigation rules are tagged as operator-enforced and are never overridden or prematurely expired by the automated engine.
  7. *Runtime Dominance (`system_settings`):* Settings follow a strict **Database-over-File** hierarchy. Operations teams can enable, tune, or instantly disable autonomous mitigation via the Web UI without editing YAML files or restarting the Collector service.

### 🎛️ Active Defense Cockpit & Control Plane (`/mitigation`) *(Collector)*
A dedicated control cockpit providing operators with complete visibility and control over fleet-wide mitigations:

- **Fleet-Wide Batch Management:** Create, extend, or revoke dynamic rules across all mitigation-enabled Valves with a single action.
- **ASN Batch Mitigation:** Expands all active subnets of an offending Autonomous System (e.g. a rogue cloud provider or proxy hosting service) into individual `/24` rules with one click, neutralizing distributed scraper waves without blocking benign third-party subnets in the same AS.
- **1-Click Triage Shortcuts:** Mitigation shortcuts integrated throughout the entire Collector interface: Investigation History drawer, Network Notes modal, Incident Explorer, Top Offender tables, and Visual Analytics views.
- **Full Audit Trail:** Every manual or automated mitigation action (creation, extension, revocation, expiration) is permanently recorded in `mitigation_audit_logs`.

### 🔔 Real-Time Alerting & Desktop Notifications *(Collector)*
- **Native Browser Desktop Notifications:** Optional opt-in to system notifications via the Web Notifications API whenever the Autonomous Defense Engine enforces a dynamic block.
- **In-App Toast Alerts:** Real-time visual toast notifications in the Collector interface for auto-mitigation events.
- **Alert Feed API:** Dedicated `/api/v1/mitigation/alerts` endpoint enabling integration with external notification tools and monitoring dashboards.

### ⚙️ Tooling & Database Enhancements
- **Interactive Configuration Helper:** `anti-dos-valve-config-helper.html` updated with dynamic mitigation parameter generators and safety guardrail presets.
- **Database Migrations (V25–V27):** Schema migrations for `dynamic_mitigation_rules`, `mitigation_audit_logs`, valve guardrail metadata, and `system_settings`.

---

## Upgrading

### Valve
Upgrading the Valve from 1.8.0 is fully backwards-compatible:
1. Replace `anti-dos-valve-1.8.0.jar` with `anti-dos-valve-1.9.0.jar` (or `anti-dos-valve-1.9.0-tomcat9.jar` for Tomcat 9).
2. Existing configurations continue to function identically. Dynamic CIDR mitigation is dormant and disabled by default until `mitigationPassword` is explicitly set in `server.xml`.

### Collector
1. Replace `anti-dos-collector-1.8.0.jar` with `anti-dos-collector-1.9.0.jar`.
2. Database migrations (V25, V26, V27) execute automatically upon startup on both SQLite and PostgreSQL backends.
3. To configure the Collector to push mitigations to Valves, add `mitigation-token` or endpoint credentials to `collector-config.yaml` as described in [`collector/SETUP_GUIDE.md`](../collector/SETUP_GUIDE.md).

