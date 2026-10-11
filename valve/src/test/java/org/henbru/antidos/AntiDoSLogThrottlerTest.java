package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AntiDoSLogThrottler}.
 */
class AntiDoSLogThrottlerTest {

	@Test
	void testDefaultMaxLogsPerSecond() {
		AntiDoSLogThrottler throttler = new AntiDoSLogThrottler();
		assertEquals(AntiDoSLogThrottler.DEFAULT_MAX_LOGS_PER_SECOND, throttler.getMaxLogsPerSecond());
		assertEquals(20, throttler.getMaxLogsPerSecond());
	}

	@Test
	void testThrottlingWithinSameSecond() {
		AntiDoSLogThrottler throttler = new AntiDoSLogThrottler(3);
		long t = 1000L;

		// First 3 should pass
		assertTrue(throttler.shouldLog(t, null));
		assertTrue(throttler.shouldLog(t + 100, null));
		assertTrue(throttler.shouldLog(t + 200, null));

		// Subsequent should be throttled
		assertFalse(throttler.shouldLog(t + 300, null));
		assertFalse(throttler.shouldLog(t + 400, null));
		assertFalse(throttler.shouldLog(t + 999, null));
	}

	@Test
	void testWindowResetAndSuppressedSummaryCallback() {
		AntiDoSLogThrottler throttler = new AntiDoSLogThrottler(2);
		AtomicLong suppressedReported = new AtomicLong(0);

		// Window 1: second 1 (t = 1000 .. 1999)
		assertTrue(throttler.shouldLog(1000L, suppressedReported::set));
		assertTrue(throttler.shouldLog(1200L, suppressedReported::set));
		assertFalse(throttler.shouldLog(1400L, suppressedReported::set));
		assertFalse(throttler.shouldLog(1600L, suppressedReported::set));
		assertFalse(throttler.shouldLog(1800L, suppressedReported::set));
		assertEquals(0, suppressedReported.get(), "No summary reported during window 1");

		// Transition to Window 2: second 2 (t = 2000)
		// Should trigger callback reporting 3 suppressed logs from window 1
		boolean allowed = throttler.shouldLog(2000L, suppressedReported::set);
		assertTrue(allowed, "First log in new window should be allowed");
		assertEquals(3, suppressedReported.get(), "Suppressed callback should report 3 suppressed logs");

		// Reset callback tracker
		suppressedReported.set(0);

		// Window 2: 2nd log allowed, 3rd throttled
		assertTrue(throttler.shouldLog(2100L, suppressedReported::set));
		assertFalse(throttler.shouldLog(2200L, suppressedReported::set));

		// Transition to Window 3: second 3 (t = 3000)
		assertTrue(throttler.shouldLog(3000L, suppressedReported::set));
		assertEquals(1, suppressedReported.get(), "Window 2 had 1 suppressed log");
	}

	@Test
	void testWindowTransitionWithoutSuppressionDoesNotInvokeCallback() {
		AntiDoSLogThrottler throttler = new AntiDoSLogThrottler(5);
		AtomicInteger callbackCount = new AtomicInteger(0);

		// Window 1: only 2 logs (under limit of 5)
		assertTrue(throttler.shouldLog(1000L, s -> callbackCount.incrementAndGet()));
		assertTrue(throttler.shouldLog(1200L, s -> callbackCount.incrementAndGet()));

		// Transition to Window 2
		assertTrue(throttler.shouldLog(2000L, s -> callbackCount.incrementAndGet()));
		assertEquals(0, callbackCount.get(), "Callback should not be called if no logs were suppressed");
	}

	@Test
	void testNegativeValueDisablesThrottling() {
		AntiDoSLogThrottler throttler = new AntiDoSLogThrottler(-1);
		long t = 1000L;

		for (int i = 0; i < 500; i++) {
			assertTrue(throttler.shouldLog(t, null), "Negative limit must allow all logs");
		}

		throttler.setMaxLogsPerSecond(-100);
		for (int i = 0; i < 100; i++) {
			assertTrue(throttler.shouldLog(t, null), "Any negative limit must disable throttling");
		}
	}

	@Test
	void testZeroSuppressesAllLogs() {
		AntiDoSLogThrottler throttler = new AntiDoSLogThrottler(0);
		AtomicLong suppressedReported = new AtomicLong(0);

		for (int i = 0; i < 5; i++) {
			assertFalse(throttler.shouldLog(1000L, suppressedReported::set), "0 limit must suppress all logs");
		}

		// Move to next window
		assertFalse(throttler.shouldLog(2000L, suppressedReported::set));
		assertEquals(5, suppressedReported.get(), "Should report 5 suppressed logs upon window transition");
	}

	@Test
	void testDynamicConfigurationChange() {
		AntiDoSLogThrottler throttler = new AntiDoSLogThrottler(2);

		// Allow 2, reject 3rd
		assertTrue(throttler.shouldLog(1000L, null));
		assertTrue(throttler.shouldLog(1100L, null));
		assertFalse(throttler.shouldLog(1200L, null));

		// Dynamically increase limit to 4
		throttler.setMaxLogsPerSecond(4);
		assertTrue(throttler.shouldLog(1300L, null));
		assertTrue(throttler.shouldLog(1400L, null));
		assertFalse(throttler.shouldLog(1500L, null));

		// Dynamically disable throttling
		throttler.setMaxLogsPerSecond(-1);
		assertTrue(throttler.shouldLog(1600L, null));
		assertTrue(throttler.shouldLog(1700L, null));
	}

	@Test
	void testConcurrentAccess() throws InterruptedException {
		final int limit = 50;
		final AntiDoSLogThrottler throttler = new AntiDoSLogThrottler(limit);
		final int threads = 10;
		final int requestsPerThread = 50;
		final ExecutorService executor = Executors.newFixedThreadPool(threads);
		final CountDownLatch startLatch = new CountDownLatch(1);
		final CountDownLatch endLatch = new CountDownLatch(threads);
		final AtomicInteger allowedCount = new AtomicInteger(0);

		final long t = 5000L;

		for (int i = 0; i < threads; i++) {
			executor.submit(() -> {
				try {
					startLatch.await();
					for (int r = 0; r < requestsPerThread; r++) {
						if (throttler.shouldLog(t, null)) {
							allowedCount.incrementAndGet();
						}
					}
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				} finally {
					endLatch.countDown();
				}
			});
		}

		startLatch.countDown();
		endLatch.await();
		executor.shutdown();

		assertEquals(limit, allowedCount.get(), "Exactly 'limit' requests should be allowed within the same window under concurrency");
	}
}
