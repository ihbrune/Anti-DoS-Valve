# Anti-DoS Collector & Fleet Manager

The **Anti-DoS Collector** is a standalone management, monitoring, and analytics service designed to aggregate security events and telemetry across a fleet of **Anti-DoS-Valve** instances running in Apache Tomcat servers.

---

## 📚 Documentation & Guides

The documentation is organized by role and responsibility:

* **[📖 Dashboard & Forensics User Guide (DASHBOARD_GUIDE.md)](DASHBOARD_GUIDE.md)**
  Comprehensive manual for **Security Analysts, Incident Responders, and Webmasters**.
  * Fleet Overview & Monitored Server Detail Views
  * Top Offender Analytics, Subnet Rollup (`/24` & `/64`), and Rotating Proxy Cluster Detection
  * Incident Explorer with multi-server CIDR filtering and exact time horizons
  * Verified Search Engine & AI Crawler Feed Management
  * System Status, Telemetry Cascades & Operational Maintenance Triggers
  * Threat Intelligence Badges & Forensic Classification Reference

* **[⚙️ Setup, Deployment & Operations Guide (SETUP_GUIDE.md)](SETUP_GUIDE.md)**
  Technical reference for **DevOps Engineers, SREs, and System Administrators**.
  * Zero-Configuration Demo Mode setup
  * Linux & systemd Production Deployment
  * Frictionless GitHub Updates (`git pull` workflow with decoupled code, config, and data)
  * Database Configuration (SQLite WAL mode vs. PostgreSQL multi-server fleet)
  * Relational Database Schema & Data Model
  * IP Enrichment Setup (Offline MaxMind/DB-IP MMDB & custom ASN overlays)
  * Data Retention & Entity Hygiene Strategy
  * REST & Forensics API Reference

---

## Features at a Glance

* **Multi-Server & Multi-Valve Telemetry:** Periodically pulls compact `/antidos-status` JSON endpoints across one or more Tomcat servers using Java 21 Virtual Threads.
* **Smart Slot Polling & Recovery:** Immutable finalized slots are pulled only once; missed slots after network interruptions are backfilled automatically without data loss.
* **Persistent Operator Knowledge & Network Notes (`/notes`):** Annotate ASNs and Subnets with Markdown notes and verdict badges (Legitimate, Internal, Suspicious, Malicious, Info) that remain completely immune to data retention cleanups.
* **Specialized Threat Forensics:** Real-time CIDR range filtering, Subnet Rollup (`/24` and `/64`), and heuristic residential proxy botnet cluster detection.
* **Dual Database Architecture:** Out-of-the-box embedded SQLite with WAL journal mode, or PostgreSQL for high-volume enterprise deployments, managed via automated Flyway migrations.
* **In-App Offline Documentation (`/help`):** Full user and operations manuals bundled directly into the application JAR with in-page contextual slide-over drawers — 100% air-gap ready without external internet dependencies.
* **Tailored Dark & Light Modes:** Modern, responsive UI with anti-FOUC theme persistence.

---

## Quickstart (Try it in 30 Seconds)

Launch the collector in **Demo Mode** against a simulated multi-server fleet without touching any production systems:

```bash
# Build the collector
mvn package -pl collector -DskipTests

# Run Demo Mode (pre-seeds 7 days of realistic attack waves and telemetry)
java -jar collector/target/anti-dos-collector-1.7.5.jar demo
```

Open **`http://localhost:8090`** in your browser.

For production deployment instructions, see [SETUP_GUIDE.md](SETUP_GUIDE.md).
