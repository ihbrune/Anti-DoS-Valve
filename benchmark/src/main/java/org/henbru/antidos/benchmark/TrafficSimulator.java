package org.henbru.antidos.benchmark;

import java.util.Random;

/**
 * High-performance, deterministic pseudorandom IP generator.
 * <p>
 * Pre-allocates IP address strings in advance so that calls to {@link #nextIp()}
 * do not allocate any String objects or perform formatting during benchmark execution.
 * Uses a fixed seed to guarantee 100% reproducible request sequences across runs.
 */
public class TrafficSimulator {

	private final String[] ipPool;
	private final TrafficDistribution distribution;
	private final double[] zipfCdf;
	private final ThreadLocal<Random> threadRandom;

	/**
	 * Default constructor with 50,000 IPs, seed 42, and Zipf distribution.
	 */
	public TrafficSimulator() {
		this(50_000, 42L, TrafficDistribution.ZIPF);
	}

	/**
	 * Creates a new simulator with specified pool size, seed, and distribution profile.
	 *
	 * @param poolSize Number of unique IP addresses to pre-generate in the pool.
	 * @param seed Fixed seed for deterministic pseudorandom sequences.
	 * @param distribution The traffic distribution profile.
	 */
	public TrafficSimulator(int poolSize, long seed, TrafficDistribution distribution) {
		if (poolSize <= 0) {
			throw new IllegalArgumentException("poolSize must be positive: " + poolSize);
		}
		this.distribution = distribution;
		this.ipPool = new String[poolSize];

		// Deterministic pre-allocation of realistic IPv4 strings (e.g. 198.51.100.x or 203.0.113.x)
		Random initRandom = new Random(seed);
		for (int i = 0; i < poolSize; i++) {
			int b1 = 10 + (initRandom.nextInt(200));
			int b2 = initRandom.nextInt(256);
			int b3 = initRandom.nextInt(256);
			int b4 = 1 + initRandom.nextInt(254);
			this.ipPool[i] = b1 + "." + b2 + "." + b3 + "." + b4;
		}

		if (distribution == TrafficDistribution.ZIPF) {
			// Precompute Cumulative Distribution Function (CDF) for fast Zipf sampling with s = 0.85
			// (Zipf exponent 0.85 roughly models 80/20 Pareto skew)
			this.zipfCdf = computeZipfCdf(poolSize, 0.85);
		} else {
			this.zipfCdf = null;
		}

		// ThreadLocal Random instance initialized deterministically per thread
		this.threadRandom = ThreadLocal.withInitial(() -> new Random(seed + Thread.currentThread().threadId()));
	}

	/**
	 * Precomputes Zipf CDF table for fast binary search sampling.
	 */
	private static double[] computeZipfCdf(int n, double s) {
		double[] cdf = new double[n];
		double sum = 0.0;
		for (int i = 1; i <= n; i++) {
			sum += 1.0 / Math.pow(i, s);
		}
		double current = 0.0;
		for (int i = 1; i <= n; i++) {
			current += (1.0 / Math.pow(i, s)) / sum;
			cdf[i - 1] = current;
		}
		// Ensure final element is exactly 1.0
		cdf[n - 1] = 1.0;
		return cdf;
	}

	/**
	 * Returns the next IP address according to the configured distribution.
	 * Zero-allocation method.
	 *
	 * @return A pre-allocated IP String from the pool.
	 */
	public String nextIp() {
		Random rng = threadRandom.get();

		return switch (distribution) {
			case UNIFORM -> {
				int idx = rng.nextInt(ipPool.length);
				yield ipPool[idx];
			}
			case BURST_ATTACK -> {
				// 99% of requests target the first 3 IPs in the pool
				if (rng.nextDouble() < 0.99) {
					yield ipPool[rng.nextInt(Math.min(3, ipPool.length))];
				} else {
					yield ipPool[rng.nextInt(ipPool.length)];
				}
			}
			case ZIPF -> {
				double p = rng.nextDouble();
				int idx = binarySearchCdf(p);
				yield ipPool[idx];
			}
		};
	}

	private int binarySearchCdf(double p) {
		int low = 0;
		int high = zipfCdf.length - 1;
		while (low < high) {
			int mid = (low + high) >>> 1;
			if (zipfCdf[mid] >= p) {
				high = mid;
			} else {
				low = mid + 1;
			}
		}
		return low;
	}

	public int getPoolSize() {
		return ipPool.length;
	}

	public TrafficDistribution getDistribution() {
		return distribution;
	}
}
