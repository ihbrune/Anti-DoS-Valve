package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Unit test for die Anti-DoS monitor implementation
 */
class AntiDoSMonitorTest {

	private static class AntiDoSMonitor4Test extends AntiDoSMonitor {
		private AntiDoSMonitor4Test(int maxCountersPerSlot,
				final int numberOfSlots, int slotLength,
				int allowedRequestsPerSlot, float shareOfRetainedOldRequests)
				throws IllegalArgumentException {
			super("TEST", maxCountersPerSlot, numberOfSlots, slotLength,
					allowedRequestsPerSlot, shareOfRetainedOldRequests);
		}

		private long referencetime = System.currentTimeMillis();

		/**
		 * This method provides a fixed value so that the same slot is always
		 * used in the monitor
		 */
		@Override
		protected long getTimeInMillis() {
			return referencetime;
		}

	}

	@Test
	void testRetainedCountCalculation() {
		int slotLength = 30;
		float anteil = (float) 0.5;
		AntiDoSMonitor4Test mon = new AntiDoSMonitor4Test(10, 3, slotLength, 3,
				anteil);

		// Slot 1 is filled
		mon.registerAndCheckRequest("123.456.789.000");
		AntiDoSCounter ip = mon.provideCurrentCounter("123.456.789.000");
		assertNotNull(ip);
		assertEquals(1, ip.getCount());
		assertEquals(0, ip.getRetainedCounts());

		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		AntiDoSCounter ip2 = mon.provideCurrentCounter("123.456.789.001");
		assertNotNull(ip2);
		assertEquals(6, ip2.getCount());
		assertEquals(0, ip2.getRetainedCounts());

		// New Slot:
		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.999");
		assertEquals(2, mon.getNumberOfActiveSlots());

		ip = mon.provideCurrentCounter("123.456.789.000");
		assertNull(ip);

		mon.registerAndCheckRequest("123.456.789.000");
		ip = mon.provideCurrentCounter("123.456.789.000");
		assertNotNull(ip);
		assertEquals(1, ip.getCount());
		int alte1 = Math.round(1 * anteil / (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte1, ip.getRetainedCounts());

		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		ip2 = mon.provideCurrentCounter("123.456.789.001");
		assertNotNull(ip2);
		assertEquals(2, ip2.getCount());
		int alte2 = Math.round(6 * anteil / (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte2, ip2.getRetainedCounts());

		// New slot:
		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.999");
		assertEquals(3, mon.getNumberOfActiveSlots());

		mon.registerAndCheckRequest("123.456.789.000");
		ip = mon.provideCurrentCounter("123.456.789.000");
		assertNotNull(ip);
		assertEquals(1, ip.getCount());
		alte1 = Math.round((1 + 1) * anteil
				/ (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte1, ip.getRetainedCounts());

		mon.registerAndCheckRequest("123.456.789.001");
		ip2 = mon.provideCurrentCounter("123.456.789.001");
		assertNotNull(ip2);
		assertEquals(1, ip2.getCount());
		alte2 = Math.round((6 + 2) * anteil
				/ (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte2, ip2.getRetainedCounts());

		// Another new slot (slot overflow):
		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.999");
		assertEquals(3, mon.getNumberOfActiveSlots());

		mon.registerAndCheckRequest("123.456.789.000");
		ip = mon.provideCurrentCounter("123.456.789.000");
		assertNotNull(ip);
		assertEquals(1, ip.getCount());
		alte1 = Math.round((1 + 1) * anteil
				/ (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte1, ip.getRetainedCounts());

		mon.registerAndCheckRequest("123.456.789.001");
		ip2 = mon.provideCurrentCounter("123.456.789.001");
		assertNotNull(ip2);
		assertEquals(1, ip2.getCount());
		alte2 = Math.round((2 + 1) * anteil
				/ (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte2, ip2.getRetainedCounts());
	}

	@Test
	void testSlotgeneration() {
		int slotLength = 30;
		int numberOfSlots = 3;
		AntiDoSMonitor4Test mon = new AntiDoSMonitor4Test(10, numberOfSlots, slotLength, 5,
				(float) 0.5);

		assertEquals(0, mon.getNumberOfActiveSlots());

		mon.registerAndCheckRequest("123.456.789.000");
		assertEquals(1, mon.getNumberOfActiveSlots());
		mon.registerAndCheckRequest("123.456.789.000");
		assertEquals(1, mon.getNumberOfActiveSlots());
		mon.registerAndCheckRequest("123.456.789.001");
		assertEquals(1, mon.getNumberOfActiveSlots());
		mon.registerAndCheckRequest("123.456.789.002");
		assertEquals(1, mon.getNumberOfActiveSlots());

		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.002");
		assertEquals(2, mon.getNumberOfActiveSlots());
		mon.registerAndCheckRequest("123.456.789.002");
		assertEquals(2, mon.getNumberOfActiveSlots());
		mon.registerAndCheckRequest("123.456.789.003");
		assertEquals(2, mon.getNumberOfActiveSlots());
		mon.registerAndCheckRequest("123.456.789.004");
		assertEquals(2, mon.getNumberOfActiveSlots());

		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.002");
		assertEquals(3, mon.getNumberOfActiveSlots());
		mon.registerAndCheckRequest("123.456.789.003");
		assertEquals(numberOfSlots, mon.getNumberOfActiveSlots());

		// Now: slot overflow
		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.012");
		assertEquals(numberOfSlots, mon.getNumberOfActiveSlots());

		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.022");
		assertEquals(numberOfSlots, mon.getNumberOfActiveSlots());
	}

	@Test
	void testMaxRequests() {
		AntiDoSMonitor mon = new AntiDoSMonitor("TEST MAX REQ", 10, 5, 30, 3, (float) 0.5);

		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertFalse(mon.registerAndCheckRequest("123.456.789.000"));
	}

	@Test
	void testSlotOverflow() {
		AntiDoSMonitor mon = new AntiDoSMonitor("TEST SLOT OVER", 1, 1, 5, 30, 2, (float) 0.5);

		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertFalse(mon.registerAndCheckRequest("123.456.789.000"));

		// A new active IP occupies activeCounters, but does NOT evict .000 from blockedCounters:
		assertTrue(mon.registerAndCheckRequest("123.456.789.001"));
		assertFalse(mon.registerAndCheckRequest("123.456.789.000"));

		// When .001 also becomes blocked, it enters blockedCounters (capacity 1) and evicts the older blocked IP:
		assertTrue(mon.registerAndCheckRequest("123.456.789.001"));
		assertFalse(mon.registerAndCheckRequest("123.456.789.001"));

		// .000 was evicted from blockedCounters after blocked overflow, so its counter is reset:
		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
	}

	@Test
	void testIsCounterBlocked() {
		AntiDoSMonitor mon = new AntiDoSMonitor("TEST IS BLOCKED", 10, 5, 30, 2, (float) 0.5);

		// Not registered yet
		assertFalse(mon.isCounterBlocked("10.0.0.1"));

		// 1 request (allowed)
		assertTrue(mon.registerAndCheckRequest("10.0.0.1"));
		assertFalse(mon.isCounterBlocked("10.0.0.1"));

		// 2 requests (limit reached, but allowed)
		assertTrue(mon.registerAndCheckRequest("10.0.0.1"));
		assertFalse(mon.isCounterBlocked("10.0.0.1"));

		// 3 requests (exceeded limit: blocked)
		assertFalse(mon.registerAndCheckRequest("10.0.0.1"));
		assertTrue(mon.isCounterBlocked("10.0.0.1"));

		// Other IP remains unblocked
		assertFalse(mon.isCounterBlocked("10.0.0.2"));
	}

	@Test
	void testRingBufferSlotAgingAndWrapAround() {
		int slotLength = 10;
		int numberOfSlots = 3;
		AntiDoSMonitor4Test mon = new AntiDoSMonitor4Test(10, numberOfSlots, slotLength, 5, 0.5f);

		// Slot 0 (t = 0)
		mon.registerAndCheckRequest("10.0.0.1");
		assertEquals(1, mon.getNumberOfActiveSlots());

		// Advance to Slot 1 (t = 10s)
		mon.referencetime += slotLength * 1000;
		mon.registerAndCheckRequest("10.0.0.1");
		assertEquals(2, mon.getNumberOfActiveSlots());

		// Advance to Slot 2 (t = 20s)
		mon.referencetime += slotLength * 1000;
		mon.registerAndCheckRequest("10.0.0.1");
		assertEquals(3, mon.getNumberOfActiveSlots());

		// Advance to Slot 3 (t = 30s) -> wraps around, overwriting slot 0 index
		mon.referencetime += slotLength * 1000;
		mon.registerAndCheckRequest("10.0.0.1");
		assertEquals(3, mon.getNumberOfActiveSlots());

		// Now simulate an idle jump of 5 intervals (t = 80s)
		mon.referencetime += slotLength * 1000 * 5;
		// Before any new request, all existing slots in the ring buffer are older than numberOfSlots:
		assertEquals(0, mon.getNumberOfActiveSlots());

		// A new request creates a fresh slot
		mon.registerAndCheckRequest("10.0.0.1");
		assertEquals(1, mon.getNumberOfActiveSlots());
		AntiDoSCounter c = mon.provideCurrentCounter("10.0.0.1");
		assertNotNull(c);
		// Retained count should be 0 because all prior slots expired
		assertEquals(0, c.getRetainedCounts());
	}

	@Test
	void testBlockLogThrottlingConfiguration() {
		AntiDoSMonitor4Test mon = new AntiDoSMonitor4Test(10, 3, 30, 2, 0.5f);
		assertEquals(AntiDoSLogThrottler.DEFAULT_MAX_LOGS_PER_SECOND, mon.getMaxBlockLogsPerSecond());

		mon.setMaxBlockLogsPerSecond(1);
		assertEquals(1, mon.getMaxBlockLogsPerSecond());

		// Exceed limit so it triggers blocking logic
		mon.registerAndCheckRequest("10.0.0.1");
		mon.registerAndCheckRequest("10.0.0.1");
		// 3rd request blocked -> throttler emits 1st log
		assertFalse(mon.registerAndCheckRequest("10.0.0.1"));
		// 4th request blocked in same interval -> throttled
		assertFalse(mon.registerAndCheckRequest("10.0.0.1"));

		// Set to -1 (disabled)
		mon.setMaxBlockLogsPerSecond(-1);
		assertEquals(-1, mon.getMaxBlockLogsPerSecond());
		assertFalse(mon.registerAndCheckRequest("10.0.0.1"));
	}
}

