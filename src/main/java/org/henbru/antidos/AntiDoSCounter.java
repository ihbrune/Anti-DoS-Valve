package org.henbru.antidos;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * Copyright 2026 Henning Brune
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 * 
 *************************
 *
 * Instances of this class are used to count occasions of similar events, for
 * example requests coming from the same IP address.
 * 
 * Uses VarHandle on primitive volatile fields to achieve zero-object-wrapper
 * atomic operations for minimal memory footprint and zero GC pressure.
 * 
 * @author Henning
 *
 */
public class AntiDoSCounter {

	private static final VarHandle COUNT;
	private static final VarHandle RETAINED_COUNTS;
	private static final VarHandle ACCESS_ORDER;

	static {
		try {
			MethodHandles.Lookup l = MethodHandles.lookup();
			COUNT = l.findVarHandle(AntiDoSCounter.class, "count", int.class);
			RETAINED_COUNTS = l.findVarHandle(AntiDoSCounter.class, "retainedCounts", int.class);
			ACCESS_ORDER = l.findVarHandle(AntiDoSCounter.class, "accessOrder", long.class);
		} catch (ReflectiveOperationException e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private volatile int count = 0;
	private volatile int retainedCounts = -1;
	private volatile long accessOrder = 0;
	private volatile boolean locked = false;

	/**
	 * Updates the access order sequence for LRU recency tracking.
	 * 
	 * @param order A monotonic sequence number
	 */
	public void touch(long order) {
		ACCESS_ORDER.setVolatile(this, order);
	}

	/**
	 * @return The sequence number when this counter was last accessed
	 */
	public long getAccessOrder() {
		return accessOrder;
	}

	/**
	 * Atomically increments the request count by 1.
	 * 
	 * @return The updated count
	 */
	public int incrementCount() {
		return (int) COUNT.getAndAdd(this, 1) + 1;
	}

	/**
	 * Atomically adds the given delta to the request count.
	 * 
	 * @param delta The value to add
	 * @return The updated count
	 */
	public int addAndGetCount(int delta) {
		return (int) COUNT.getAndAdd(this, delta) + delta;
	}

	/**
	 * @return The current access count
	 */
	public int getCount() {
		return count;
	}

	/**
	 * Sets the count directly to the specified value.
	 * 
	 * @param value The new count
	 */
	public void setCount(int value) {
		COUNT.setVolatile(this, value);
	}

	/**
	 * @return Access numbers taken from previous measurement intervals (slots).
	 *         Initial value is -1 to distinguish uninitialized state.
	 */
	public int getRetainedCounts() {
		return retainedCounts;
	}

	/**
	 * Sets the retained counts to the specified value.
	 * 
	 * @param value The new retained count
	 */
	public void setRetainedCounts(int value) {
		RETAINED_COUNTS.setVolatile(this, value);
	}

	/**
	 * Atomically adds the given delta to the retained counts.
	 * 
	 * @param delta The value to add
	 * @return The updated retained count
	 */
	public int addAndGetRetainedCounts(int delta) {
		return (int) RETAINED_COUNTS.getAndAdd(this, delta) + delta;
	}

	/**
	 * Atomically sets the retained count to newValue if current value == expected.
	 * 
	 * @param expected The expected current value
	 * @param newValue The new value to set
	 * @return true if successful
	 */
	public boolean compareAndSetRetainedCounts(int expected, int newValue) {
		return RETAINED_COUNTS.compareAndSet(this, expected, newValue);
	}

	/**
	 * @return The sum of current count and retained counts
	 */
	public int getCountCombined() {
		int current = count;
		int retained = retainedCounts;
		return retained < 0 ? current : current + retained;
	}

	/**
	 * @return Query of the lock status
	 */
	public boolean isLocked() {
		return locked;
	}

	/**
	 * Flags this counter as locked.
	 */
	public void lock() {
		this.locked = true;
	}

	@Override
	public String toString() {
		return "Count:" + getCount() + " Retained:" + getRetainedCounts() + " Locked:" + (locked ? "yes" : "no");
	}
}
