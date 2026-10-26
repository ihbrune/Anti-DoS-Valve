package org.henbru.antidos.benchmark;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Integrated Benchmark Runner and History Recorder.
 * <p>
 * Executes:
 * 1. {@link BaselineBenchmark} (Raw concurrent JDK baseline)
 * 2. {@link AntiDoSMonitorBenchmark} (Monitor throughput with & without returning visitor counters)
 * 3. {@link AntiDoSVisitorTokenBenchmark} (AES-256-GCM token creation, validation & pipeline)
 * <p>
 * Computes hardware-independent relative performance scores, records the run details
 * into {@code .benchmarks/history.jsonl}, and prints a consolidated report.
 */
public class BenchmarkRunner {

	private static final Path HISTORY_DIR = Paths.get(".benchmarks");
	private static final Path HISTORY_FILE = HISTORY_DIR.resolve("history.jsonl");

	public static void main(String[] args) throws Exception {
		System.out.println("====================================================================================================");
		System.out.println("  Anti-DoS-Valve Benchmark Suite");
		System.out.println("====================================================================================================");
		System.out.println("JVM:        " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")");
		System.out.println("OS:         " + System.getProperty("os.name") + " " + System.getProperty("os.arch"));
		System.out.println("CPU Cores:  " + Runtime.getRuntime().availableProcessors());
		String gitCommit = resolveGitCommit();
		System.out.println("Git Commit: " + gitCommit);
		System.out.println("----------------------------------------------------------------------------------------------------");

		// 1. Run Baseline Benchmark
		System.out.println("1/3 Running Baseline Benchmark (Raw ConcurrentMap)...");
		Options baselineOptions = new OptionsBuilder()
				.include(BaselineBenchmark.class.getSimpleName())
				.warmupIterations(2)
				.measurementIterations(3)
				.forks(0)
				.build();

		Collection<RunResult> baselineResults = new Runner(baselineOptions).run();
		double baselineThroughput = extractPrimaryThroughput(baselineResults);

		// 2. Run Monitor Benchmark
		System.out.println("\n2/3 Running AntiDoSMonitor Benchmark (In-Memory Concurrency)...");
		Options monitorOptions = new OptionsBuilder()
				.include(AntiDoSMonitorBenchmark.class.getSimpleName())
				.warmupIterations(2)
				.measurementIterations(3)
				.forks(0)
				.build();

		Collection<RunResult> monitorResults = new Runner(monitorOptions).run();
		Map<String, Double> monitorThroughputs = extractMonitorThroughputs(monitorResults);

		// 3. Run Visitor Token Benchmark
		System.out.println("\n3/3 Running AntiDoSVisitorToken Benchmark (AES-256-GCM Crypto Pipeline)...");
		Options tokenOptions = new OptionsBuilder()
				.include(AntiDoSVisitorTokenBenchmark.class.getSimpleName())
				.warmupIterations(2)
				.measurementIterations(3)
				.forks(0)
				.build();

		Collection<RunResult> tokenResults = new Runner(tokenOptions).run();
		Map<String, Double> tokenThroughputs = extractTokenThroughputs(tokenResults);

		// 4. Calculate Relative Scores, Print Summary & Record
		System.out.println("\n====================================================================================================");
		System.out.println("  BENCHMARK SUMMARY & RELATIVE RATIOS");
		System.out.println("====================================================================================================");
		System.out.printf("%-46s | %-16s | %-14s | %-20s%n", "Benchmark / Scenario", "Throughput (ops/s)", "Relative Score", "Category");
		System.out.println("-----------------------------------------------+------------------+----------------+---------------------");
		System.out.printf("%-46s | %13.2f op/s | %12s | %-20s%n", "Baseline (ConcurrentMap)", baselineThroughput, "1.000 (Ref)", "JDK Baseline");

		Files.createDirectories(HISTORY_DIR);
		String isoTimestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

		// Print and log monitor results
		for (Map.Entry<String, Double> entry : monitorThroughputs.entrySet()) {
			String name = entry.getKey();
			double throughput = entry.getValue();
			double relativeScore = baselineThroughput > 0 ? (throughput / baselineThroughput) : 0.0;

			System.out.printf("%-46s | %13.2f op/s | %12.4f | %-20s%n", name, throughput, relativeScore, "Monitor Concurrency");

			// Maintain backwards-compatible history.jsonl records for standard dists
			String dist = name.replace("Monitor [", "").replace("]", "");
			String jsonRecord = String.format(
					java.util.Locale.ROOT,
					"{\"timestamp\":\"%s\",\"commit\":\"%s\",\"java\":\"%s\",\"cores\":%d,\"dist\":\"%s\",\"baselineOps\":%.2f,\"monitorOps\":%.2f,\"relativeScore\":%.4f}%n",
					isoTimestamp, gitCommit, System.getProperty("java.version"),
					Runtime.getRuntime().availableProcessors(), dist, baselineThroughput, throughput, relativeScore
			);
			Files.writeString(HISTORY_FILE, jsonRecord, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
		}

		// Print and log token crypto results
		for (Map.Entry<String, Double> entry : tokenThroughputs.entrySet()) {
			String name = entry.getKey();
			double throughput = entry.getValue();
			double relativeScore = baselineThroughput > 0 ? (throughput / baselineThroughput) : 0.0;

			System.out.printf("%-46s | %13.2f op/s | %12.4f | %-20s%n", name, throughput, relativeScore, "Crypto AES-256-GCM");

			String jsonRecord = String.format(
					java.util.Locale.ROOT,
					"{\"timestamp\":\"%s\",\"commit\":\"%s\",\"java\":\"%s\",\"cores\":%d,\"dist\":\"%s\",\"baselineOps\":%.2f,\"monitorOps\":%.2f,\"relativeScore\":%.4f}%n",
					isoTimestamp, gitCommit, System.getProperty("java.version"),
					Runtime.getRuntime().availableProcessors(), name, baselineThroughput, throughput, relativeScore
			);
			Files.writeString(HISTORY_FILE, jsonRecord, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
		}

		System.out.println("----------------------------------------------------------------------------------------------------");
		System.out.println("Result appended to: " + HISTORY_FILE.toAbsolutePath());
		System.out.println("====================================================================================================\n");
	}

	private static double extractPrimaryThroughput(Collection<RunResult> results) {
		for (RunResult res : results) {
			return res.getPrimaryResult().getScore();
		}
		return 0.0;
	}

	private static Map<String, Double> extractMonitorThroughputs(Collection<RunResult> results) {
		Map<String, Double> map = new LinkedHashMap<>();
		for (RunResult res : results) {
			String method = res.getPrimaryResult().getLabel();
			String dist = res.getParams().getParam("distributionName");
			if (dist == null) {
				dist = "ZIPF";
			}
			String suffix = "registerAndCheckRequestReturningVisitor".equals(method) ? " (Returning Visitor)" : "";
			String key = "Monitor [" + dist + suffix + "]";
			map.put(key, res.getPrimaryResult().getScore());
		}
		return map;
	}

	private static Map<String, Double> extractTokenThroughputs(Collection<RunResult> results) {
		Map<String, Double> map = new LinkedHashMap<>();
		for (RunResult res : results) {
			String method = res.getPrimaryResult().getLabel();
			String name = switch (method) {
				case "validateToken_Valid" -> "VisitorToken [Validate Valid Token]";
				case "createToken_New" -> "VisitorToken [Create New Token (IV+AES)]";
				case "validateToken_Tampered" -> "VisitorToken [Reject Tampered Token]";
				case "fullPipeline_ReturningVisitor" -> "VisitorToken [Full Pipeline (Token + Monitor)]";
				default -> "VisitorToken [" + method + "]";
			};
			map.put(name, res.getPrimaryResult().getScore());
		}
		return map;
	}

	private static String resolveGitCommit() {
		try {
			Process proc = new ProcessBuilder("git", "rev-parse", "--short", "HEAD").start();
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
				String line = reader.readLine();
				if (line != null && !line.trim().isEmpty()) {
					return line.trim();
				}
			}
		} catch (java.io.IOException | RuntimeException ignored) {
		}
		return "unknown";
	}
}
