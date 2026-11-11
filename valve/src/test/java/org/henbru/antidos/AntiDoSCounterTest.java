package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Unit test for the counter implementation
 */
class AntiDoSCounterTest {

	@Test
	void testCount() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getCount());
		rec.incrementCount();
		assertEquals(1, rec.getCount());
		rec.addAndGetCount(1);
		assertEquals(2, rec.getCount());
		rec.setCount(1);
		assertEquals(1, rec.getCount());
		rec.setCount(100);
		assertEquals(100, rec.getCount());
	}

	@Test
	void testRetainedCounts() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(-1, rec.getRetainedCounts());
		rec.addAndGetRetainedCounts(1);
		assertEquals(0, rec.getRetainedCounts());
		rec.addAndGetRetainedCounts(1);
		assertEquals(1, rec.getRetainedCounts());
		rec.addAndGetRetainedCounts(1);
		assertEquals(2, rec.getRetainedCounts());
		rec.setRetainedCounts(1);
		assertEquals(1, rec.getRetainedCounts());
		assertTrue(rec.compareAndSetRetainedCounts(1, 5));
		assertEquals(5, rec.getRetainedCounts());
		assertFalse(rec.compareAndSetRetainedCounts(1, 10));
		assertEquals(5, rec.getRetainedCounts());
	}

	@Test
	void testCountCombined() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getCountCombined());

		rec.incrementCount();
		assertEquals(1, rec.getCountCombined());

		rec.addAndGetCount(1);
		assertEquals(2, rec.getCountCombined());

		rec.setRetainedCounts(123);
		assertEquals(125, rec.getCountCombined());
	}

	@Test
	void testTouch() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getAccessOrder());

		long t0 = System.nanoTime();
		rec.touch();
		long t1 = System.nanoTime();

		assertTrue(rec.getAccessOrder() >= t0);
		assertTrue(rec.getAccessOrder() <= t1);

		rec.touch(42L);
		assertEquals(42L, rec.getAccessOrder());
	}

	@Test
	void testReturningCount() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getReturningCount());
		rec.incrementReturningCount();
		assertEquals(1, rec.getReturningCount());
		rec.addAndGetReturningCount(4);
		assertEquals(5, rec.getReturningCount());
		rec.setReturningCount(10);
		assertEquals(10, rec.getReturningCount());
		assertTrue(rec.toString().contains("Returning:10"));
	}

	@Test
	void testRecordSampleIfAbsent() {
		AntiDoSCounter counter = new AntiDoSCounter();
		assertFalse(counter.isLocked());
		assertEquals(null, counter.getSample());

		boolean recorded = counter.recordSampleIfAbsent("POST", "/wp-login.php?user=admin&pwd=secret", "curl/7.88.1");
		assertTrue(recorded);

		AntiDoSCounter.SampleRequest sample = counter.getSample();
		assertEquals("POST", sample.method());
		assertEquals("/wp-login.php", sample.uri()); // query string stripped!
		assertEquals("curl/7.88.1", sample.userAgent());
		assertFalse(sample.authenticated());

		// Second call must NOT overwrite the first sample
		boolean second = counter.recordSampleIfAbsent("GET", "/other", "other-ua", true);
		assertFalse(second);
		assertEquals("POST", counter.getSample().method());
		assertEquals("/wp-login.php", counter.getSample().uri());
		assertFalse(counter.getSample().authenticated());
	}

	@Test
	void testRecordSampleAuthenticated() {
		AntiDoSCounter counter = new AntiDoSCounter();
		assertTrue(counter.recordSampleIfAbsent("GET", "/dashboard", "Mozilla/5.0", true));
		assertNotNull(counter.getSample());
		assertTrue(counter.getSample().authenticated());
	}

	@Test
	void testSampleSanitizationAndLimits() {
		AntiDoSCounter counter = new AntiDoSCounter();

		// Excessively long URI and UA, newlines/control chars
		String longUri = "/api/" + "a".repeat(500);
		String maliciousUa = "BadBot\r\nInjectedHeader: value\u0000" + "x".repeat(200);

		assertTrue(counter.recordSampleIfAbsent("post", longUri, maliciousUa));

		AntiDoSCounter.SampleRequest sample = counter.getSample();
		assertEquals("POST", sample.method());
		assertTrue(sample.uri().length() <= 256);
		assertTrue(sample.userAgent().length() <= 128);
		assertFalse(sample.userAgent().contains("\r"));
		assertFalse(sample.userAgent().contains("\n"));
		assertFalse(sample.userAgent().contains("\u0000"));
	}

	@Test
	void testUserAgentCardinalityTracking() {
		AntiDoSCounter counter = new AntiDoSCounter();
		assertFalse(counter.hasUserAgentTracker());
		assertEquals(0, counter.getDistinctUserAgents());
		assertEquals(0L, counter.getUaCardinalityBits());

		// Register single User-Agent
		counter.registerUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
		assertTrue(counter.hasUserAgentTracker());
		assertEquals(1, counter.getDistinctUserAgents());
		long firstBits = counter.getUaCardinalityBits();
		assertTrue(firstBits != 0L);

		// Register same User-Agent again (idempotent, distinct count unchanged)
		counter.registerUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
		assertEquals(1, counter.getDistinctUserAgents());
		assertEquals(firstBits, counter.getUaCardinalityBits());

		// Register multiple distinct User-Agents
		counter.registerUserAgent("curl/7.88.1");
		counter.registerUserAgent("python-requests/2.31.0");
		counter.registerUserAgent("Googlebot/2.1");
		assertTrue(counter.getDistinctUserAgents() >= 2);
		assertTrue(counter.getDistinctUserAgents() <= 4);

		// Test merging bits
		AntiDoSCounter other = new AntiDoSCounter();
		other.registerUserAgent("Custom-Scanner/1.0");
		counter.mergeUaCardinalityBits(other.getUaCardinalityBits());
		assertTrue(counter.getDistinctUserAgents() >= other.getDistinctUserAgents());
	}
}
