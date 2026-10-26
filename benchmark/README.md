# Anti-DoS Benchmark Suite (`anti-dos-benchmark`)

A standalone performance test harness and traffic load simulator for the **Anti-DoS-Valve** project using **JMH (Java Microbenchmark Harness)**.

---

## 1. Rationale & Design Goals

As the Valve evolves (e.g. tracking login status, parsing user-agent headers, subnet partitions), maintaining ultra-low latency and zero GC overhead in Tomcat's request processing path is mission-critical.

This suite addresses four core testing needs:

1. **Deterministic Traffic Simulator (`TrafficSimulator`):**
   * Pre-allocates realistic IP address pools (`zero-allocation` during benchmark execution).
   * Generates pseudorandom IP sequences from a fixed seed (100% reproducible across runs).
   * Models realistic distributions:
     * `ZIPF`: Power-law (80/20 Pareto skew) representing real web and crawler traffic.
     * `BURST_ATTACK`: Concentrated flood (99% traffic on top 3 IPs) testing immediate rate-limiting and lock contention.
     * `UNIFORM`: Equal-probability distribution across 50,000+ IPs stressing map sizing and eviction.

2. **Hardware-Normalized Baseline (`BaselineBenchmark`):**
   * Machine performance varies widely between developer laptops, battery vs. AC power, OS scheduling, and CI runners.
   * `BaselineBenchmark` measures raw concurrent throughput of JDK primitives (`ConcurrentHashMap` + `LongAdder`) under identical traffic streams.
   * By computing the **Relative Performance Score** (`Monitor Throughput / Baseline Throughput`), we obtain a hardware-independent performance coefficient that remains meaningful across machines.

3. **Monitor Concurrency Measurement (`AntiDoSMonitorBenchmark`):**
   * Measures `AntiDoSMonitor.registerAndCheckRequest(ip)` under multi-threaded load simulating Tomcat worker threads (`@Threads(MAX)`).
   * Compares untracked requests vs. requests with returning visitor telemetry (`returningVisitor = true`).
   * Detects regressions in throughput, lock contention, and slot rotation.

4. **Cryptographic Visitor Token Engine (`AntiDoSVisitorTokenBenchmark`):**
   * Isolates the performance of the AES-256-GCM authenticated encryption engine (`AntiDoSVisitorTokenService`).
   * Evaluates:
     * `validateToken_Valid`: Returning visitor fast-path (Base64 decode + AES-GCM decrypt + AEAD tag verification).
     * `createToken_New`: First-contact / refresh path (SecureRandom 12-byte IV + AES-GCM encrypt + Base64URL encode).
     * `validateToken_Tampered`: Rejection speed on authentication tag failure.
     * `fullPipeline_ReturningVisitor`: End-to-end composite of token validation followed by monitor counter registration.

5. **Persistent History Tracking (`.benchmarks/`):**
   * Benchmark runs are logged to `.benchmarks/history.jsonl`.
   * The `.benchmarks/` directory is intentionally excluded from Git (`.gitignore`) to avoid polluting the repository with local machine variations, while surviving `mvn clean`.
   * Facilitates local trend analysis across Git branches and commits.

---

## 2. Quickstart & Execution Commands

### Compile & Build Benchmark JAR
```bash
mvn package -pl valve,benchmark -DskipTests
```
This produces an executable standalone uber-jar at `benchmark/target/benchmarks.jar`.

### Run Automated Runner (Baseline + Monitor + VisitorToken + History Recording)
```bash
java -cp benchmark/target/benchmarks.jar org.henbru.antidos.benchmark.BenchmarkRunner
```
* Sample output:
```text
====================================================================================================
  BENCHMARK SUMMARY & RELATIVE RATIOS
====================================================================================================
Benchmark / Scenario                           | Throughput (ops/s) | Relative Score | Category            
-----------------------------------------------+------------------+----------------+---------------------
Baseline (ConcurrentMap)                       |   98796284.62 op/s |  1.000 (Ref) | JDK Baseline        
Monitor [ZIPF]                                 |   14732289.65 op/s |       0.1491 | Monitor Concurrency 
Monitor [BURST_ATTACK]                         |    7024601.81 op/s |       0.0711 | Monitor Concurrency 
Monitor [ZIPF (Returning Visitor)]             |   14644394.33 op/s |       0.1482 | Monitor Concurrency 
Monitor [BURST_ATTACK (Returning Visitor)]     |    7011494.59 op/s |       0.0710 | Monitor Concurrency 
VisitorToken [Create New Token (IV+AES)]       |    2067986.43 op/s |       0.0209 | Crypto AES-256-GCM  
VisitorToken [Full Pipeline (Token + Monitor)] |    7585767.11 op/s |       0.0768 | Crypto AES-256-GCM  
VisitorToken [Reject Tampered Token]           |    6622263.43 op/s |       0.0670 | Crypto AES-256-GCM  
VisitorToken [Validate Valid Token]            |    9927570.27 op/s |       0.1005 | Crypto AES-256-GCM  
----------------------------------------------------------------------------------------------------
Result appended to: .benchmarks/history.jsonl
====================================================================================================
```

### Run Direct JMH Command-Line
You can also run standard JMH commands with custom iterations or profilers:
```bash
# Run monitor benchmark only
java -jar benchmark/target/benchmarks.jar AntiDoSMonitorBenchmark -f 1 -wi 2 -i 3

# Run with GC allocation profiler (inspects heap bytes allocated per op)
java -jar benchmark/target/benchmarks.jar AntiDoSMonitorBenchmark -prof gc -f 1 -wi 1 -i 2
```

---

## 3. History File Format (`.benchmarks/history.jsonl`)

Each run appends single-line JSON records:
```json
{"timestamp":"2026-10-24T10:45:00Z","commit":"e4a81b9","java":"21.0.2","cores":12,"dist":"ZIPF","baselineOps":28450123.45,"monitorOps":18230456.78,"relativeScore":0.6408}
```
