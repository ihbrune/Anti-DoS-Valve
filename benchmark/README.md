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
   * Detects regressions in throughput, lock contention, and slot rotation.

4. **Persistent History Tracking (`.benchmarks/`):**
   * Benchmark runs are logged to `.benchmarks/history.jsonl`.
   * The `.benchmarks/` directory is intentionally excluded from Git (`.gitignore`) to avoid polluting the repository with local machine variations, while surviving `mvn clean`.
   * Facilitates local trend analysis across Git branches and commits.

---

## 2. Quickstart & Execution Commands

### Compile & Build Benchmark JAR
```bash
mvn package -pl benchmark -DskipTests
```
This produces an executable standalone uber-jar at `benchmark/target/benchmarks.jar`.

### Run Automated Runner (Baseline + Monitor + History Recording)
```bash
java -cp benchmark/target/benchmarks.jar org.henbru.antidos.benchmark.BenchmarkRunner
```
* Sample output:
```text
================================================================================
  BENCHMARK SUMMARY & RELATIVE RATIOS
================================================================================
Benchmark / Distribution       | Throughput (ops/s) | Relative Score
-------------------------------+------------------+-------------
Baseline (ConcurrentMap)       |   28450123.45 op/s | 1.00 (Ref)
Monitor [ZIPF]                 |   18230456.78 op/s |      0.641
Monitor [BURST_ATTACK]         |   16102940.12 op/s |      0.566
--------------------------------------------------------------------------------
Result appended to: .benchmarks/history.jsonl
================================================================================
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
