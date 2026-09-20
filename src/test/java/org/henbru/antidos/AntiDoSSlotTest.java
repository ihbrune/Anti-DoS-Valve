package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Unit test for the slot implementation
 */
class AntiDoSSlotTest {

	@Test
	void testContents() {
		AntiDoSSlot slot = new AntiDoSSlot(null, 1L, 10);

		assertNull(slot.getCounterIfExists("123.456.789.000"));
		assertNotNull(slot.getCounter("123.456.789.000"));

		AntiDoSCounter rec = slot.getCounter("123.456.789.000");
		rec.setCount(11);
		AntiDoSCounter rec2 = slot.getCounter("123.456.789.000");
		assertEquals(11, rec.getCountCombined());
		assertEquals(11, rec2.getCountCombined());

		rec2.incrementCount();
		assertEquals(12, rec.getCountCombined());
		assertEquals(12, rec2.getCountCombined());

	}

	@Test
	void testCounterCacheOverflow() {

		AntiDoSSlot slot = provideSlotTestdata1();
		AntiDoSCounter checkRec = slot.getCounterIfExists("123.456.789.004");
		assertNotNull(checkRec);
		assertEquals(14, checkRec.getCountCombined());

		slot = provideSlotTestdata1();
		checkRec = slot.getCounterIfExists("123.456.789.003");
		assertNotNull(checkRec);
		assertEquals(13, checkRec.getCountCombined());

		slot = provideSlotTestdata1();
		checkRec = slot.getCounterIfExists("123.456.789.002");
		assertNotNull(checkRec);
		assertEquals(12, checkRec.getCountCombined());

		slot = provideSlotTestdata1();
		checkRec = slot.getCounterIfExists("123.456.789.001");
		assertNull(checkRec);

		// --------------

		slot = provideSlotTestdata2();
		checkRec = slot.getCounterIfExists("123.456.789.004");
		assertNotNull(checkRec);
		assertEquals(14, checkRec.getCountCombined());

		slot = provideSlotTestdata2();
		checkRec = slot.getCounterIfExists("123.456.789.003");
		assertNotNull(checkRec);
		assertEquals(13, checkRec.getCountCombined());

		slot = provideSlotTestdata2();
		checkRec = slot.getCounterIfExists("123.456.789.002");
		assertNull(checkRec);

		slot = provideSlotTestdata2();
		checkRec = slot.getCounterIfExists("123.456.789.001");
		assertNotNull(checkRec);
		assertEquals(11, checkRec.getCountCombined());

	}

	/**
	 * Testdata returning a slot with a max counter number of 3 and 4 previous
	 * calls to {@link AntiDoSSlot#getCounter(String)} with 4 different counter
	 * names
	 */
	private static AntiDoSSlot provideSlotTestdata1() {
		AntiDoSSlot slot = new AntiDoSSlot("TD1", 1L, 3);

		AntiDoSCounter rec1 = slot.getCounter("123.456.789.001");
		rec1.setCount(11);
		AntiDoSCounter rec2 = slot.getCounter("123.456.789.002");
		rec2.setCount(12);
		AntiDoSCounter rec3 = slot.getCounter("123.456.789.003");
		rec3.setCount(13);
		AntiDoSCounter rec4 = slot.getCounter("123.456.789.004");
		rec4.setCount(14);

		return slot;
	}

	/**
	 * Testdata returning a slot with a max counter number of 3 and 4 previous
	 * calls to {@link AntiDoSSlot#getCounter(String)} with 3 different counter
	 * names. The first counter name is used two times (1. und 3. call)
	 */
	private static AntiDoSSlot provideSlotTestdata2() {
		AntiDoSSlot slot = new AntiDoSSlot("TD2", 2L, 3);

		AntiDoSCounter rec1 = slot.getCounter("123.456.789.001");
		rec1.setCount(11);
		AntiDoSCounter rec2 = slot.getCounter("123.456.789.002");
		rec2.setCount(12);

		slot.getCounter("123.456.789.001");

		AntiDoSCounter rec3 = slot.getCounter("123.456.789.003");
		rec3.setCount(13);
		AntiDoSCounter rec4 = slot.getCounter("123.456.789.004");
		rec4.setCount(14);

		return slot;
	}

	@Test
	void testTwoTierCacheSeparationAndEviction() {
		// Active capacity 2, Blocked capacity 2
		AntiDoSSlot slot = new AntiDoSSlot("TEST", 1L, 2, 2);

		// Add 2 active counters
		AntiDoSCounter c1 = slot.getCounter("1.1.1.1");
		slot.getCounter("2.2.2.2");
		assertEquals(2, slot.getActiveCounterCount());
		assertEquals(0, slot.getBlockedCounterCount());

		// Block 1.1.1.1 -> moves to blockedCounters, active counters now has only 1!
		c1.lock();
		slot.blockCounter("1.1.1.1", c1);
		assertEquals(1, slot.getActiveCounterCount());
		assertEquals(1, slot.getBlockedCounterCount());

		// Can add 3.3.3.3 and 4.4.4.4 to active without evicting 1.1.1.1
		AntiDoSCounter c3 = slot.getCounter("3.3.3.3");
		AntiDoSCounter c4 = slot.getCounter("4.4.4.4");
		assertEquals(2, slot.getActiveCounterCount());
		assertEquals(1, slot.getBlockedCounterCount());

		// 1.1.1.1 is still safely in slot (in blockedCounters)
		assertNotNull(slot.getCounterIfExists("1.1.1.1"));
		// 2.2.2.2 was oldest active entry, so it was evicted by 4.4.4.4
		assertNull(slot.getCounterIfExists("2.2.2.2"));
		assertNotNull(slot.getCounterIfExists("3.3.3.3"));
		assertNotNull(slot.getCounterIfExists("4.4.4.4"));

		// Now block 3.3.3.3 and 4.4.4.4 -> blockedCounters will have 1.1.1.1, 3.3.3.3, 4.4.4.4 (exceeding blocked capacity 2)
		c3.lock();
		slot.blockCounter("3.3.3.3", c3);
		assertEquals(2, slot.getBlockedCounterCount());

		c4.lock();
		slot.blockCounter("4.4.4.4", c4);
		assertEquals(2, slot.getBlockedCounterCount());

		// 1.1.1.1 was the oldest blocked entry, so it was evicted when blocked capacity 2 was exceeded by 4.4.4.4
		assertNull(slot.getCounterIfExists("1.1.1.1"));
		assertNotNull(slot.getCounterIfExists("3.3.3.3"));
		assertNotNull(slot.getCounterIfExists("4.4.4.4"));
	}

	@Test
	void testBlockedCounterCountIncrement() {
		AntiDoSSlot slot = new AntiDoSSlot("TEST", 1L, 2, 2);
		AntiDoSCounter c1 = slot.getCounter("1.1.1.1");
		c1.setCount(10);
		c1.lock();
		slot.blockCounter("1.1.1.1", c1);

		// When blocked IP sends another request, getCounter retrieves it and count can be incremented
		AntiDoSCounter c1Retrieved = slot.getCounter("1.1.1.1");
		assertSame(c1, c1Retrieved);
		assertTrue(c1Retrieved.isLocked());
		c1Retrieved.incrementCount();
		assertEquals(11, c1Retrieved.getCount());
	}
}
