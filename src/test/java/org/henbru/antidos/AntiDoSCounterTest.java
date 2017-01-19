package org.henbru.antidos;

import org.henbru.antidos.AntiDoSCounter;

import junit.framework.TestCase;

/**
 * Unit test for the counter implementation
 */
public class AntiDoSCounterTest extends TestCase {

	public void testCount() {
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
	
	public void testRetainedCounts() {
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
	public void testCountCombined() {
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
