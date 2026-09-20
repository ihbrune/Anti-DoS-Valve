package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
}
