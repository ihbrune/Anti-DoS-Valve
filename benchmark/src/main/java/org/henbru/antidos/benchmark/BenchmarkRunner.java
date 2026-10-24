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
import java.util.HashMap;
import java.util.Map;

import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Integrated Benchmark Runner and History Recorder.
 * <p>
 * Executes both {@link BaselineBenchmark} and {@link AntiDoSMonitorBenchmark},
 * computes the hardware-independent relative performance score, records the
 * run details into {@code .benchmarks/history.jsonl}, and prints a consolidated report.
 */
public class BenchmarkRunner {

	private static final Path HISTORY_DIR = Paths.get(".benchmarks");
	private static final Path HISTORY_FILE = HISTORY_DIR.resolve("history.jsonl");

	public static void main(String[] args) throws Exception {
		System.out.println("================================================================================");
		System.out.println("  Anti-DoS-Valve Benchmark Suite");
		System.out.println("================================================================================");
		System.out.println("JVM:        " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")");
		System.out.println("OS:         " + System.getProperty("os.name") + " " + System.getProperty("os.arch"));
		System.out.println("CPU Cores:  " + Runtime.getRuntime().availableProcessors());
		String gitCommit = resolveGitCommit();
		System.out.println("Git Commit: " + gitCommit);
		System.out.println("--------------------------------------------------------------------------------");

		// 1. Run Baseline Benchmark
		System.out.println("Running Baseline Benchmark (Raw ConcurrentMap)...");
		Options baselineOptions = new OptionsBuilder()
				.include(BaselineBenchmark.class.getSimpleName())
				.warmupIterations(2)
				.measurementIterations(3)
				.forks(0)
				.build();

		Collection<RunResult> baselineResults = new Runner(baselineOptions).run();
		double baselineThroughput = extractPrimaryThroughput(baselineResults);

		// 2. Run Monitor Benchmark
		System.out.println("\nRunning AntiDoSMonitor Benchmark...");
		Options monitorOptions = new OptionsBuilder()
				.include(AntiDoSMonitorBenchmark.class.getSimpleName())
				.warmupIterations(2)
				.measurementIterations(3)
				.forks(0)
				.build();

		Collection<RunResult> monitorResults = new Runner(monitorOptions).run();
		Map<String, Double> monitorThroughputs = extractThroughputsByParam(monitorResults);

		// 3. Calculate Relative Scores and Record
		System.out.println("\n================================================================================");
		System.out.println("  BENCHMARK SUMMARY & RELATIVE RATIOS");
		System.out.println("================================================================================");
		System.out.printf("%-30s | %-16s | %-12s%n", "Benchmark / Distribution", "Throughput (ops/s)", "Relative Score");
		System.out.println("-------------------------------+------------------+-------------");
		System.out.printf("%-30s | %13.2f op/s | %10s%n", "Baseline (ConcurrentMap)", baselineThroughput, "1.00 (Ref)");

		Files.createDirectories(HISTORY_DIR);
		String isoTimestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

		for (Map.Entry<String, Double> entry : monitorThroughputs.entrySet()) {
			String dist = entry.getKey();
			double throughput = entry.getValue();
			double relativeScore = baselineThroughput > 0 ? (throughput / baselineThroughput) : 0.0;

			System.out.printf("%-30s | %13.2f op/s | %10.3f%n", "Monitor [" + dist + "]", throughput, relativeScore);

			// Append single-line JSON record into .benchmarks/history.jsonl
			String jsonRecord = String.format(
					java.util.Locale.ROOT,
					"{\"timestamp\":\"%s\",\"commit\":\"%s\",\"java\":\"%s\",\"cores\":%d,\"dist\":\"%s\",\"baselineOps\":%.2f,\"monitorOps\":%.2f,\"relativeScore\":%.4f}%n",
					isoTimestamp, gitCommit, System.getProperty("java.version"),
					Runtime.getRuntime().availableProcessors(), dist, baselineThroughput, throughput, relativeScore
			);
			Files.writeString(HISTORY_FILE, jsonRecord, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
		}

		System.out.println("--------------------------------------------------------------------------------");
		System.out.println("Result appended to: " + HISTORY_FILE.toAbsolutePath());
		System.out.println("================================================================================\n");
	}

	private static double extractPrimaryThroughput(Collection<RunResult> results) {
		for (RunResult res : results) {
			return res.getPrimaryResult().getScore();
		}
		return 0.0;
	}

	private static Map<String, Double> extractThroughputsByParam(Collection<RunResult> results) {
		Map<String, Double> map = new HashMap<>();
		for (RunResult res : results) {
			String distParam = res.getParams().getParam("distributionName");
			if (distParam == null) {
				distParam = "DEFAULT";
			}
			map.put(distParam, res.getPrimaryResult().getScore());
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
