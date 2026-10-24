# Benchmark Module: Agent & Developer Guide

This document guides AI coding assistants and developers maintaining or extending the benchmark harness in `benchmark/`.

---

## 1. Architectural Principles

1. **Isolation from Core Valve Runtime:**
   * `benchmark/` depends on `valve/`, never vice versa.
   * `valve/` runtime dependencies must strictly remain **zero**. JMH and testing dependencies must never leak into `valve/pom.xml`.
2. **Zero-Allocation in Simulator Hot Path:**
   * Any generator feeding benchmarks (`TrafficSimulator`) must pre-allocate strings or buffers during `@Setup`.
   * Generating random strings or using `String.format` inside `@Benchmark` methods corrupts measurements and adds artificial GC pressure.
3. **Hardware Normalization:**
   * Never compare raw `ops/s` between different hardware runs directly.
   * Always look at the **`relativeScore`** (`Monitor Throughput / Baseline Throughput`). A degradation of > 10% in `relativeScore` signals a concurrency regression or lock contention issue.
4. **Reproducibility:**
   * Always preserve pseudorandom determinism with explicit seeds.
   * When adding new traffic profiles (e.g., subnet bursts or IPv6 patterns), ensure they can be instantiated reproducibly.

---

## 2. Key Classes & Responsibilities

| Class | Role |
|---|---|
| `TrafficSimulator` | Deterministic IP stream generator with pre-allocated IP pools and Zipf/Burst/Uniform distribution support. |
| `BaselineBenchmark` | Pure JDK concurrent collection reference benchmark measuring peak hardware capability. |
| `AntiDoSMonitorBenchmark` | JMH benchmark evaluating `AntiDoSMonitor.registerAndCheckRequest()`. |
| `BenchmarkRunner` | Consolidated test orchestrator that runs baseline + monitor, computes relative scores, and logs to `.benchmarks/history.jsonl`. |

---

## 3. Workflow for Performance Verification of Valve Changes

Whenever making critical changes to `valve/` (e.g. adding login-state checks, user-agent parsing, counter modifications):

1. **Checkout base commit:**
   ```bash
   mvn package -pl benchmark -DskipTests
   java -cp benchmark/target/benchmarks.jar org.henbru.antidos.benchmark.BenchmarkRunner
   ```
2. **Apply changes & re-run:**
   ```bash
   mvn package -pl benchmark -DskipTests
   java -cp benchmark/target/benchmarks.jar org.henbru.antidos.benchmark.BenchmarkRunner
   ```
3. **Compare `.benchmarks/history.jsonl`:**
   Inspect `relativeScore` before and after to verify that the change did not introduce performance regressions or lock contentions.
