package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;

import org.apache.catalina.core.StandardEngine;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the asynchronous batch eviction, circuit breaker hard-cap protection,
 * and adaptive threshold mechanics in {@link AntiDoSSlot}, {@link AntiDoSMonitor}, and {@link AntiDoSValve}.
 */
class AntiDoSAsyncEvictionTest {

	@Test
	void testThresholdAutoDetection() {
		// Default threshold is 500
		AntiDoSSlot slotSync = new AntiDoSSlot("TEST_SYNC", "s1", 500);
		assertFalse(slotSync.isAsyncEvictionActive());

		AntiDoSSlot slotAsync = new AntiDoSSlot("TEST_ASYNC", "s2", 501);
		assertTrue(slotAsync.isAsyncEvictionActive());
	}

	@Test
	void testExplicitAsyncEvictionOverride() {
		AntiDoSSlot slot = new AntiDoSSlot("TEST_OVERRIDE", "s1", 10);
		assertFalse(slot.isAsyncEvictionActive());

		slot.setAsyncEviction(true);
		assertTrue(slot.isAsyncEvictionActive());

		slot.setAsyncEviction(false);
		assertFalse(slot.isAsyncEvictionActive());

		slot.setAsyncEviction(null);
		assertFalse(slot.isAsyncEvictionActive()); // reverts to threshold <= 500 -> false
	}

	@Test
	void testMonitorAndValvePropagation() {
		AntiDoSValve valve = new AntiDoSValve();
		valve.setContainer(new StandardEngine());
		valve.setMonitorName("PROP_TEST");
		valve.setNumberOfSlots(5);
		valve.setSlotLength(10);
		valve.setAllowedRequestsPerSlot(100);
		valve.setShareOfRetainedFormerRequests("0.0");
		valve.setMaxIPCacheSize(100); // <= 500 -> defaults to sync
		assertNull(valve.reloadMonitor());

		AntiDoSMonitor monitor = valve.provideMonitor();
		assertNotNull(monitor);
		assertNull(valve.getAsyncEviction());
		assertNull(monitor.getAsyncEviction());

		// Override via valve
		valve.setAsyncEviction(true);
		assertEquals(Boolean.TRUE, valve.getAsyncEviction());
		assertEquals(Boolean.TRUE, monitor.getAsyncEviction());

		// Trigger slot creation and verify slot inherited setting
		assertTrue(monitor.registerAndCheckRequest("192.168.1.1"));
		assertEquals(1, monitor.getNumberOfActiveSlots());
	}

	@Test
	void testAsyncBatchEvictionWithHysteresis() throws Exception {
		int maxCounters = 20;
		// 90% low watermark = 18 counters
		AntiDoSSlot slot = new AntiDoSSlot("TEST_HYSTERESIS", "s1", maxCounters);
		slot.setAsyncEviction(true);

		CountDownLatch latch = new CountDownLatch(1);
		slot.setEvictionExecutor(cmd -> ForkJoinPool.commonPool().execute(() -> {
			try {
				cmd.run();
			} finally {
				latch.countDown();
			}
		}));

		// Fill up to capacity (20 entries)
		for (int i = 1; i <= maxCounters; i++) {
			AntiDoSCounter c = slot.getCounter("ip-" + i);
			assertNotNull(c);
		}
		assertEquals(maxCounters, slot.getActiveCounterCount());

		// Add 21st counter, triggering async eviction
		AntiDoSCounter c21 = slot.getCounter("ip-21");
		assertNotNull(c21);

		// Wait for background worker to complete eviction down to low watermark
		assertTrue(latch.await(3, TimeUnit.SECONDS), "Async eviction should complete within timeout");

		// Low watermark is 90% of 20 = 18. (Plus 1 new = 19 max)
		int finalCount = slot.getActiveCounterCount();
		assertTrue(finalCount <= 19, "Active counter count should have dropped near low watermark, but was: " + finalCount);

		// Oldest entries (ip-1, ip-2) should have been evicted first
		assertNull(slot.getCounterIfExists("ip-1"));
		// Most recent entries should still exist
		assertNotNull(slot.getCounterIfExists("ip-20"));
		assertNotNull(slot.getCounterIfExists("ip-21"));
	}

	@Test
	void testCircuitBreakerHardCapProtection() {
		int maxCounters = 10;
		// Hard cap is ceil(10 * 1.2) = 12
		AntiDoSSlot slot = new AntiDoSSlot("TEST_HARD_CAP", "s1", maxCounters);
		slot.setAsyncEviction(true);
		slot.setEvictionExecutor(r -> {}); // Prevent background eviction race while populating test entries

		// Manually populate up to hard cap (12 entries)
		for (int i = 1; i <= 12; i++) {
			slot.getCounter("ip-" + i);
		}
		assertEquals(12, slot.getActiveCounterCount());

		// Next request arrives when size >= 12 (hard cap reached)
		// Should return transient counter without increasing map size
		AntiDoSCounter overflowCounter = slot.getCounter("overflow-ip");
		assertNotNull(overflowCounter);
		assertTrue(slot.getActiveCounterCount() <= 12, "Active counters should not exceed hard-cap 12");
		assertNull(slot.getCounterIfExists("overflow-ip"), "Overflow IP should not be permanently stored in map");

		// Known existing IPs should still be found normally if not yet evicted
		AntiDoSCounter c12 = slot.getCounter("ip-12");
		assertNotNull(c12);
		assertTrue(slot.getActiveCounterCount() <= 12);
	}

	@Test
	void testCircuitBreakerInMonitorAllowsTraffic() {
		int maxCounters = 10;
		AntiDoSMonitor monitor = new AntiDoSMonitor("CIRCUIT_BREAKER_MON", maxCounters, 5, 10, 100, 0.0f);
		monitor.setAsyncEviction(true);

		// Saturate slot up to hard-cap (12 entries)
		for (int i = 1; i <= 12; i++) {
			assertTrue(monitor.registerAndCheckRequest("10.0.0." + i));
		}

		// When hard-cap is reached, new IP is still evaluated as allowed (pass-through with count 1)
		assertTrue(monitor.registerAndCheckRequest("10.0.0.999"));
		// Total requests still incremented
		assertEquals(13, monitor.getTotalrequests());

		monitor.shutdown();
	}

	@Test
	void testValveLifecycleShutdown() throws Exception {
		AntiDoSValve valve = new AntiDoSValve();
		valve.setContainer(new StandardEngine());
		valve.setMonitorName("LIFECYCLE_SHUTDOWN_TEST");
		valve.setNumberOfSlots(2);
		valve.setSlotLength(5);
		valve.setAllowedRequestsPerSlot(50);
		valve.setShareOfRetainedFormerRequests("0.0");
		valve.setMaxIPCacheSize(1000); // triggers async mode

		valve.start();
		assertTrue(valve.isRequestAllowed("192.168.1.1", "/api"));
		valve.stop();
		// Repeated calls to stop should be idempotent
		valve.stop();
	}

	@Test
	void testBlockedHardCapRetainsCounterInActiveAndRemainsBlocked() {
		// Active capacity 50, Blocked capacity 10 -> Hard cap for blocked is ceil(10 * 1.2) = 12
		AntiDoSSlot slot = new AntiDoSSlot("BLOCKED_HARD_CAP", "s1", 50, 10);
		slot.setAsyncEviction(true);
		slot.setEvictionExecutor(r -> {}); // Prevent background eviction race while populating test entries

		// Fill blockedCounters up to hard-cap (12 entries)
		for (int i = 1; i <= 12; i++) {
			AntiDoSCounter c = slot.getCounter("blocked-" + i);
			c.lock();
			slot.blockCounter("blocked-" + i, c);
		}
		assertEquals(12, slot.getBlockedCounterCount());

		// Now add an active counter that gets locked
		AntiDoSCounter activeVictim = slot.getCounter("new-attacker");
		assertNotNull(activeVictim);
		activeVictim.lock();

		// Attempt to move to blockedCounters -> blocked hard-cap reached
		slot.blockCounter("new-attacker", activeVictim);

		// Blocked capacity should remain bounded at 12
		assertTrue(slot.getBlockedCounterCount() <= 12, "Blocked counters should not exceed hard-cap 12");

		// The counter MUST be retained in activeCounters so it is not lost or 'pardoned'
		assertNotNull(slot.getCounterIfExists("new-attacker"));
		AntiDoSCounter retrieved = slot.getCounter("new-attacker");
		assertSame(activeVictim, retrieved);
		assertTrue(retrieved.isLocked(), "Counter must still be flagged as locked");
	}

	@Test
	void testSafeEvictionDoesNotEvictTouchedCounter() throws Exception {
		// Slot capacity 10, low-watermark is 9.
		// Triggering at 10 will evict 1 entry (10 - 9 = 1).
		AntiDoSSlot slot = new AntiDoSSlot("SAFE_EVICT_TEST", "s1", 10);
		slot.setAsyncEviction(true);

		// Populate 10 entries. ip-1 is the oldest.
		for (int i = 1; i <= 10; i++) {
			slot.getCounter("ip-" + i);
		}
		assertEquals(10, slot.getActiveCounterCount());

		// Hook up a single-thread executor with latch
		CountDownLatch readyLatch = new CountDownLatch(1);
		CountDownLatch proceedLatch = new CountDownLatch(1);
		Executor controlledExecutor = r -> {
			Thread t = new Thread(() -> {
				readyLatch.countDown();
				try {
					proceedLatch.await();
				} catch (InterruptedException ignored) {
				}
				r.run();
			});
			t.start();
		};
		slot.setEvictionExecutor(controlledExecutor);

		// Insert 11th entry -> triggers eviction dispatch
		slot.getCounter("ip-11");
		readyLatch.await(2, TimeUnit.SECONDS);

		// While eviction worker is waiting to run, simulate that ip-1 receives new traffic (gets touched)
		AntiDoSCounter c1 = slot.getCounter("ip-1");
		assertNotNull(c1);

		// Allow eviction task to run
		proceedLatch.countDown();
		Thread.sleep(100);

		// Because ip-1 was touched again, its accessOrder changed and it MUST NOT have been evicted!
		assertNotNull(slot.getCounterIfExists("ip-1"), "ip-1 was touched during eviction and must not be evicted");
	}

	@Test
	void testTransientCounterUnderHardCapHasZeroRetained() {
		int maxCounters = 10;
		AntiDoSSlot slot = new AntiDoSSlot("TRANSIENT_RETAINED_TEST", "s1", maxCounters);
		slot.setAsyncEviction(true);

		// Fill to hard-cap (12)
		for (int i = 1; i <= 12; i++) {
			slot.getCounter("client-" + i);
		}

		// 13th IP hits hard cap
		AntiDoSCounter transientCounter = slot.getCounter("client-overflow");
		assertNotNull(transientCounter);
		assertEquals(0, transientCounter.getRetainedCounts(),
				"Transient counter under hard-cap must have retainedCounts initialized to 0 to skip multi-slot scans");
	}
}
