# Release Notes – Version 1.7.0

Version 1.7.0 is a feature and hardening release providing enhanced time-series observability, slot history inspection, customizable collector limits, deterministic pipeline ordering, security response headers, and memory lifecycle fixes.

---

## Highlights

### 📊 Historical Slot Inspection & Timeline Metrics
Monitoring collectors and operators can now inspect finished, historical time windows:
- **Last Completed Slot (`slot=previous`):** Returns the fully completed time window preceding the active slot, ensuring collectors obtain stable metrics without counting jitter.
- **Direct Slot Query (`slot=<slotKey>`):** Query any active ring buffer slot by its chronological slot key.
- **Slot Metrics:** Each slot in the timeline and JSON API now tracks total request counts alongside active and blocked IP tallies.
- **Always Forbidden Block Counter:** Tracks the lifetime number of requests blocked by `alwaysForbiddenIPs`.

### ⚡ Customizable Collector Limits & Resource Protection
- **`limit` Parameter:** Tailor client lists in JSON and HTML views (`?limit=100`, `?limit=all`, `?limit=-1`).
- **Browser Protection Cap:** HTML table views automatically cap rendered clients at 1,000 to prevent browser freezing and excessive memory allocation during large-scale DDoS events.
- **Safe Limit Fallbacks:** Non-positive values (`0`, invalid strings) safely fall back to the default limit (50) instead of unbounded extraction.
- **Strict Slot Resolution:** Unknown or evicted slot keys return `null` instead of silently falling back to the current active slot.

### 🛡️ Security Hardening
- **HTTP Security Headers:** The status dashboard now emits standard security headers on both HTML and JSON responses:
  - `Cache-Control: no-store, no-cache, must-revalidate`
  - `Pragma: no-cache`
  - `Referrer-Policy: no-referrer` (prevents status access tokens from leaking via HTTP Referer headers)
  - `X-Content-Type-Options: nosniff`
  - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'`
- **Clean Slot Typing:** Slot type categorization (`current`, `previous`, `historical`) strictly checks elapsed time windows and never reflects unvalidated user input.

### 🚀 Performance & Lifecycle Fixes
- **Zero-Allocation Pipeline Ordering:** Ordering of multiple valves across container tiers (Engine, Host, Context) is now deterministic and computed linearly without redundant re-sorting.
- **Lifecycle & Memory Leak Prevention:** Fixed a side effect where rendering valve order could inadvertently retain stopped valves in JVM memory after a web application reload.
- **Lock-Free Request Path:** Maintained zero runtime dependencies and 100% lock-free concurrency (`LongAdder`) in the request processing path.

### ⚙️ Configuration Refinements
- **`shareOfRetainedFormerRequests` is now Optional:** Defaults to `0` (no historical retention carried over), matching standard rate-limiting setups without requiring explicit configuration.
- **Config Helper Synchronized:** Updated `anti-dos-valve-config-helper.html` to treat `shareOfRetainedFormerRequests` as optional with default `0`.

---

## Upgrading

Upgrading to 1.7.0 is fully backwards-compatible:
1. Replace `anti-dos-valve-1.6.0.jar` with `anti-dos-valve-1.7.0.jar` (or `anti-dos-valve-1.7.0-tomcat9.jar` for Tomcat 9).
2. Existing configurations continue to work without modification.
