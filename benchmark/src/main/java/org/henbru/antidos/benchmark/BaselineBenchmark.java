package org.henbru.antidos.benchmark;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

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
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Hardware baseline benchmark.
 * <p>
 * Measures the raw concurrent throughput of standard JDK concurrency primitives
 * ({@link ConcurrentHashMap} with {@link LongAdder}) using the exact same
 * {@link TrafficSimulator} IP streams as the AntiDoS monitor tests.
 * <p>
 * This metric represents the maximum theoretical throughput the current hardware/JVM
 * can deliver for concurrent IP counter lookups without any valve logic.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class BaselineBenchmark {

	@Param({"ZIPF"})
	private String distributionName;

	private TrafficSimulator trafficSimulator;
	private ConcurrentHashMap<String, LongAdder> rawMap;

	@Setup
	public void setup() {
		TrafficDistribution dist = TrafficDistribution.valueOf(distributionName);
		this.trafficSimulator = new TrafficSimulator(20_000, 42L, dist);
		this.rawMap = new ConcurrentHashMap<>(4096);
	}

	@Benchmark
	@Threads(Threads.MAX)
	public long baselineConcurrentMapIncrement() {
		String ip = trafficSimulator.nextIp();
		LongAdder adder = rawMap.computeIfAbsent(ip, k -> new LongAdder());
		adder.increment();
		return adder.sum();
	}
}
