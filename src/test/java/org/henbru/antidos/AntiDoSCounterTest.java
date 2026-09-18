package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Unit test for the counter implementation
 */
class AntiDoSCounterTest {

	@Test
	void testCount() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getCount().get());
		rec.getCount().addAndGet(1);		
		assertEquals(1, rec.getCount().get());
		rec.getCount().addAndGet(1);		
		assertEquals(2, rec.getCount().get());
		rec.getCount().set(1);		
		assertEquals(1, rec.getCount().get());
		rec.getCount().set(100);		
		assertEquals(100, rec.getCount().get());		
	}
	
	@Test
	void testRetainedCounts() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(-1, rec.getRetainedCounts().get());
		rec.getRetainedCounts().addAndGet(1);		
		assertEquals(0, rec.getRetainedCounts().get());
		rec.getRetainedCounts().addAndGet(1);		
		assertEquals(1, rec.getRetainedCounts().get());
		rec.getRetainedCounts().addAndGet(1);		
		assertEquals(2, rec.getRetainedCounts().get());
		rec.getRetainedCounts().set(1);		
		assertEquals(1, rec.getRetainedCounts().get());
		
	}

	@Test
	void testCountCombined() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getCountCombined());
		
		rec.getCount().addAndGet(1);		
		assertEquals(1, rec.getCountCombined());
		
		rec.getCount().addAndGet(1);		
		assertEquals(2, rec.getCountCombined());
		
		rec.getRetainedCounts().set(123);		
		assertEquals(125, rec.getCountCombined());
	}	
}
