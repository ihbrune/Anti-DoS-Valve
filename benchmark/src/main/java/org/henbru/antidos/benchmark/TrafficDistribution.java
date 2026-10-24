package org.henbru.antidos.benchmark;

/**
 * Traffic distribution profiles for simulating realistic HTTP request patterns.
 */
public enum TrafficDistribution {

	/**
	 * Zipfian / Power-law distribution (e.g. Pareto 80/20).
	 * A small fraction of IP addresses generates the majority of requests,
	 * while a large number of IPs generate only 1-2 requests.
	 * Closely models real-world web traffic and distributed scraping.
	 */
	ZIPF,

	/**
	 * Uniform distribution across the entire IP pool.
	 * Every IP in the pool has equal probability of being selected.
	 * Stresses cache size, hash table distribution, and memory eviction.
	 */
	UNIFORM,

	/**
	 * Concentrated burst attack.
	 * A tiny set of 1-3 attacker IPs generates 99%+ of all requests,
	 * provoking immediate rate-limiting and high lock/counter contention.
	 */
	BURST_ATTACK
}
