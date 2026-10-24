package org.henbru.antidos.benchmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

public class TrafficSimulatorTest {

	@Test
	public void testDeterministicSequenceWithFixedSeed() {
		TrafficSimulator sim1 = new TrafficSimulator(100, 12345L, TrafficDistribution.UNIFORM);
		TrafficSimulator sim2 = new TrafficSimulator(100, 12345L, TrafficDistribution.UNIFORM);

		for (int i = 0; i < 50; i++) {
			assertEquals(sim1.nextIp(), sim2.nextIp(), "Generators with identical seeds must produce identical IP sequences");
		}
	}

	@Test
	public void testBurstAttackDistributionConcentration() {
		TrafficSimulator sim = new TrafficSimulator(50, 42L, TrafficDistribution.BURST_ATTACK);
		Map<String, Integer> counts = new HashMap<>();

		int total = 10_000;
		for (int i = 0; i < total; i++) {
			String ip = sim.nextIp();
			assertNotNull(ip);
			counts.merge(ip, 1, Integer::sum);
		}

		// Find the top 3 IPs
		int top3Count = counts.values().stream()
				.sorted((a, b) -> Integer.compare(b, a))
				.limit(3)
				.mapToInt(Integer::intValue)
				.sum();

		double ratio = (double) top3Count / total;
		assertTrue(ratio > 0.95, "BURST_ATTACK should route > 95% of traffic to top 3 IPs, was: " + ratio);
	}

	@Test
	public void testZipfDistributionSkew() {
		TrafficSimulator sim = new TrafficSimulator(100, 42L, TrafficDistribution.ZIPF);
		Map<String, Integer> counts = new HashMap<>();

		int total = 20_000;
		for (int i = 0; i < total; i++) {
			counts.merge(sim.nextIp(), 1, Integer::sum);
		}

		// Top 20% of IPs should receive significantly more traffic than bottom 80%
		int top20Count = counts.values().stream()
				.sorted((a, b) -> Integer.compare(b, a))
				.limit(20)
				.mapToInt(Integer::intValue)
				.sum();

		double ratio = (double) top20Count / total;
		assertTrue(ratio > 0.60, "ZIPF distribution should exhibit clear skew (>60% in top 20%), was: " + ratio);
	}
}
