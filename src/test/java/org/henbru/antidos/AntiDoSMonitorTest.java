package org.henbru.antidos;

import java.util.Calendar;

import org.henbru.antidos.AntiDoSCounter;
import org.henbru.antidos.AntiDoSMonitor;

import junit.framework.TestCase;

/**
 * Unit test for die Anti-DoS monitor implementation
 */
public class AntiDoSMonitorTest extends TestCase {

	private static class AntiDoSMonitor4Test extends AntiDoSMonitor {
		private AntiDoSMonitor4Test(int maxCountersPerSlot,
				final int numberOfSlots, int slotLength,
				int allowedRequestsPerSlot, float shareOfRetainedOldRequests)
				throws IllegalArgumentException {
			super(maxCountersPerSlot, numberOfSlots, slotLength,
					allowedRequestsPerSlot, shareOfRetainedOldRequests);
		}

		private long referencetime = Calendar.getInstance().getTimeInMillis();

		/**
		 * This method provides a fixed value so that the same slot is always
		 * used in the monitor
		 */
		@Override
		protected long getTimeInMillis() {
			return referencetime;
		}

	}

	public void testRetainedCountCalculation() {
		int slotLength = 30;
		float anteil = (float) 0.5;
		AntiDoSMonitor4Test mon = new AntiDoSMonitor4Test(10, 3, slotLength, 3,
				anteil);

		// Slot 1 is filled
		mon.registerAndCheckRequest("123.456.789.000");
		AntiDoSCounter ip = mon.provideCurrentCounter("123.456.789.000");
		assertNotNull(ip);
		assertEquals(1, ip.getCount().get());
		assertEquals(0, ip.getRetainedCounts().get());

		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		AntiDoSCounter ip2 = mon.provideCurrentCounter("123.456.789.001");
		assertNotNull(ip2);
		assertEquals(6, ip2.getCount().get());
		assertEquals(0, ip2.getRetainedCounts().get());

		// New Slot:
		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.999");
		assertEquals(2, mon.getNumberOfActiveSlots());

		ip = mon.provideCurrentCounter("123.456.789.000");
		assertNull(ip);

		mon.registerAndCheckRequest("123.456.789.000");
		ip = mon.provideCurrentCounter("123.456.789.000");
		assertNotNull(ip);
		assertEquals(1, ip.getCount().get());
		int alte1 = Math.round(1 * anteil / (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte1, ip.getRetainedCounts().get());

		mon.registerAndCheckRequest("123.456.789.001");
		mon.registerAndCheckRequest("123.456.789.001");
		ip2 = mon.provideCurrentCounter("123.456.789.001");
		assertNotNull(ip2);
		assertEquals(2, ip2.getCount().get());
		int alte2 = Math.round(6 * anteil / (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte2, ip2.getRetainedCounts().get());

		// New slot:
		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.999");
		assertEquals(3, mon.getNumberOfActiveSlots());

		mon.registerAndCheckRequest("123.456.789.000");
		ip = mon.provideCurrentCounter("123.456.789.000");
		assertNotNull(ip);
		assertEquals(1, ip.getCount().get());
		alte1 = Math.round((1 + 1) * anteil
				/ (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte1, ip.getRetainedCounts().get());

		mon.registerAndCheckRequest("123.456.789.001");
		ip2 = mon.provideCurrentCounter("123.456.789.001");
		assertNotNull(ip2);
		assertEquals(1, ip2.getCount().get());
		alte2 = Math.round((6 + 2) * anteil
				/ (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte2, ip2.getRetainedCounts().get());

		// Another new slot (slot overflow):
		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.999");
		assertEquals(3, mon.getNumberOfActiveSlots());

		mon.registerAndCheckRequest("123.456.789.000");
		ip = mon.provideCurrentCounter("123.456.789.000");
		assertNotNull(ip);
		assertEquals(1, ip.getCount().get());
		alte1 = Math.round((1 + 1) * anteil
				/ (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte1, ip.getRetainedCounts().get());

		mon.registerAndCheckRequest("123.456.789.001");
		ip2 = mon.provideCurrentCounter("123.456.789.001");
		assertNotNull(ip2);
		assertEquals(1, ip2.getCount().get());
		alte2 = Math.round((2 + 1) * anteil
				/ (mon.getNumberOfActiveSlots() - 1));
		assertEquals(alte2, ip2.getRetainedCounts().get());
	}

	public void testSlotgeneration() {
		int slotLength = 30;
		AntiDoSMonitor4Test mon = new AntiDoSMonitor4Test(10, 3, slotLength, 3,
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
		assertEquals(3, mon.getNumberOfActiveSlots());

		// Now: slot overflow
		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.012");
		assertEquals(3, mon.getNumberOfActiveSlots());

		mon.referencetime += slotLength * 1000 + 1;
		mon.registerAndCheckRequest("123.456.789.022");
		assertEquals(3, mon.getNumberOfActiveSlots());
	}

	public void testMaxRequests() {
		AntiDoSMonitor mon = new AntiDoSMonitor(10, 5, 30, 3, (float) 0.5);

		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertFalse(mon.registerAndCheckRequest("123.456.789.000"));
	}

	public void testSlotOverflow() {
		AntiDoSMonitor mon = new AntiDoSMonitor(1, 5, 30, 2, (float) 0.5);

		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
		assertFalse(mon.registerAndCheckRequest("123.456.789.000"));

		assertTrue(mon.registerAndCheckRequest("123.456.789.001"));

		assertTrue(mon.registerAndCheckRequest("123.456.789.000"));
	}

}
