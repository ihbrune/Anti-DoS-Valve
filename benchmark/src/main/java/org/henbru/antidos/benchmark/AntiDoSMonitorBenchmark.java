package org.henbru.antidos.benchmark;

import java.util.concurrent.TimeUnit;

import org.henbru.antidos.AntiDoSMonitor;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

/**
 * High-concurrency benchmark for {@link AntiDoSMonitor}.
 * <p>
 * Evaluates request check throughput, blocking efficiency, and lock contention
 * under realistic pseudorandom traffic distributions.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class AntiDoSMonitorBenchmark {

	@Param({"ZIPF", "BURST_ATTACK"})
	private String distributionName;

	private TrafficSimulator trafficSimulator;
	private AntiDoSMonitor monitor;

	@Setup
	public void setup() {
		TrafficDistribution dist = TrafficDistribution.valueOf(distributionName);
		this.trafficSimulator = new TrafficSimulator(20_000, 42L, dist);

		// Initialize monitor with typical production configuration
		this.monitor = new AntiDoSMonitor(
				"BenchmarkMonitor",
				20_000, // maxCountersPerSlot
				10_000, // maxBlockedCountersPerSlot
				10,     // numberOfSlots
				60,     // slotLength in seconds
				100,    // allowedRequestsPerSlot
				0.5f    // shareOfRetainedFormerRequests
		);
	}

	@TearDown
	public void tearDown() {
		if (monitor != null) {
			monitor.shutdown();
		}
	}

	@Benchmark
	@Threads(Threads.MAX)
	public boolean registerAndCheckRequest() {
		String ip = trafficSimulator.nextIp();
		return monitor.registerAndCheckRequest(ip);
	}

	@Benchmark
	@Threads(Threads.MAX)
	public boolean registerAndCheckRequestReturningVisitor() {
		String ip = trafficSimulator.nextIp();
		return monitor.registerAndCheckRequest(ip, ip, null, false, 0, 0, true);
	}
}
