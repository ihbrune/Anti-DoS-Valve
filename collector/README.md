# Anti-DoS Collector & Dashboard

The **Anti-DoS Collector** is a standalone management and analytics service designed to aggregate security events and metrics across a fleet of **Anti-DoS-Valve** instances running in multiple Tomcat servers.

---

## Features

* **Multi-Server & Multi-Valve Telemetry:** Periodically polls configured `/antidos-status` JSON endpoints across one or more servers.
* **Smart Slot Polling & Recovery:**
  * Automatically retrieves finalized previous slots (`slot=previous&limit=all`).
  * Supports intermediate polling for long-window valves (e.g. 15-minute subnet aggregators) via in-progress slot upserts.
  * Recovers missed slots automatically using `slot=<slotKey>` if network connectivity was temporarily interrupted.
* **Flexible Storage (Zero-Ops to Enterprise Scale):**
  * **SQLite (Default):** Runs immediately out-of-the-box with zero configuration (`antidos-collector.db`).
  * **PostgreSQL:** Switchable via JDBC connection string in `application.yaml` or environment variables for high-volume enterprise deployments.
  * Versioned schema migrations managed automatically via **Flyway**.
* **Modern HTMX Dashboard:**
  * Real-time fleet overview showing all connected servers and valves.
  * Top offending IP addresses and subnets correlated across servers.
  * Interactive incident timeline and filtering without client-side Node.js/npm dependencies.
* **CLI Onboarding Tool:** Built-in command to test connectivity, verify tokens, and generate ready-to-use configuration blocks.

---

## Quickstart

### 1. Build the Collector
From the root directory of the project:
```bash
mvn package -pl collector
```
This produces the executable Spring Boot JAR in `collector/target/anti-dos-collector-1.7.0.jar`.

### 2. Configure Monitored Endpoints
Copy the provided example configuration file:
```bash
cp collector/src/main/resources/collector-config.example.yaml collector-config.yaml
```
Edit `collector-config.yaml` to specify your Tomcat server endpoints and status tokens:
```yaml
collector:
  poll-interval-seconds: 15
  endpoints:
    - name: "Web-Node-1"
      url: "http://localhost:8080/antidos-status"
      token: "secretToken1"
      poll-intermediate-slots: false
```

### 3. Verify an Endpoint via CLI
You can test connectivity to any Valve endpoint before running the service:
```bash
java -jar collector/target/anti-dos-collector-1.7.0.jar test-endpoint \
  --url "http://localhost:8080/antidos-status" \
  --token "secretToken1" \
  --name "Web-Node-1"
```

### 4. Run the Collector
```bash
java -jar collector/target/anti-dos-collector-1.7.0.jar
```
Open your browser at **`http://localhost:8090`** to access the Fleet Dashboard.

---

## Database Configuration

### SQLite (Default)
By default, the collector stores data in a local SQLite database named `antidos-collector.db` in the current working directory.

To ensure the database is always stored in a fixed location regardless of the working directory from which you launch the collector, specify a fixed or home-relative path:

**Via `collector-config.yaml`:**
```yaml
spring:
  datasource:
    url: "jdbc:sqlite:${user.home}/.antidos/antidos-collector.db"
    # or an absolute path:
    # url: "jdbc:sqlite:/var/lib/antidos/antidos-collector.db"
```

**Via Environment Variable:**
```bash
export SPRING_DATASOURCE_URL="jdbc:sqlite:${HOME}/.antidos/antidos-collector.db"
```

*Note:* The Collector automatically creates any missing parent directories (e.g. `~/.antidos/`) upon startup.

### PostgreSQL (Production Fleet)
To connect to a PostgreSQL database, provide standard Spring Data Source environment variables or edit `collector-config.yaml`:
```bash
export SPRING_DATASOURCE_URL="jdbc:postgresql://localhost:5432/antidos_collector"
export SPRING_DATASOURCE_USERNAME="postgres"
export SPRING_DATASOURCE_PASSWORD="password"
java -jar collector/target/anti-dos-collector-1.7.0.jar
```
Flyway will automatically initialize the PostgreSQL schema upon startup.

