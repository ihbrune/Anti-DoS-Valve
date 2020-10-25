package org.henbru.antidos;

import junit.framework.TestCase;

/**
 * Unit test for the slot implementation
 */
public class AntiDoSSlotTest extends TestCase {

	public void testContents() {
		AntiDoSSlot slot = new AntiDoSSlot(null, "xx", 10);

		assertNull(slot.getCounterIfExists("123.456.789.000"));
		assertNotNull(slot.getCounter("123.456.789.000"));

		AntiDoSCounter rec = slot.getCounter("123.456.789.000");
		rec.getCount().set(11);
		AntiDoSCounter rec2 = slot.getCounter("123.456.789.000");
		assertEquals(11, rec.getCountCombined());
		assertEquals(11, rec2.getCountCombined());

		rec2.getCount().addAndGet(1);
		assertEquals(12, rec.getCountCombined());
		assertEquals(12, rec2.getCountCombined());

	}

	public void testCounterCacheOverflow() {

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
		AntiDoSSlot slot = new AntiDoSSlot("TD1", "xx", 3);

		AntiDoSCounter rec1 = slot.getCounter("123.456.789.001");
		rec1.getCount().set(11);
		AntiDoSCounter rec2 = slot.getCounter("123.456.789.002");
		rec2.getCount().set(12);
		AntiDoSCounter rec3 = slot.getCounter("123.456.789.003");
		rec3.getCount().set(13);
		AntiDoSCounter rec4 = slot.getCounter("123.456.789.004");
		rec4.getCount().set(14);

		return slot;
	}

	/**
	 * Testdata returning a slot with a max counter number of 3 and 4 previous
	 * calls to {@link AntiDoSSlot#getCounter(String)} with 3 different counter
	 * names. The first counter name is used two times (1. und 3. call)
	 */
	private static AntiDoSSlot provideSlotTestdata2() {
		AntiDoSSlot slot = new AntiDoSSlot("TD2", "xx", 3);

		AntiDoSCounter rec1 = slot.getCounter("123.456.789.001");
		rec1.getCount().set(11);
		AntiDoSCounter rec2 = slot.getCounter("123.456.789.002");
		rec2.getCount().set(12);

		slot.getCounter("123.456.789.001");

		AntiDoSCounter rec3 = slot.getCounter("123.456.789.003");
		rec3.getCount().set(13);
		AntiDoSCounter rec4 = slot.getCounter("123.456.789.004");
		rec4.getCount().set(14);

		return slot;
	}
}
