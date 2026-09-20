package org.henbru.antidos;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.atomic.LongAdder;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

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
 * This class implements the access rate limitation. In essence, it is a buffer
 * of successive time slots, which hold counters for 'something', for example
 * the IP addresses of web requests. The decision about blocking a request is
 * then made based of these counters. These checks are made in method
 * {@link #registerAndCheckRequest(String)}
 * 
 * @author Henning
 *
 */
public class AntiDoSMonitor {

	private static final Log log = LogFactory.getLog(AntiDoSValve.ANTIDOS_LOGGER_NAME);

	private String monitorName;
	private String name4logging;
	private int maxCountersPerSlot;
	private int maxBlockedCountersPerSlot;
	private final int numberOfSlots;
	private final AtomicReferenceArray<AntiDoSSlot> slots;
	private final Object slotCreationLock = new Object();
	private int slotLength;
	private int allowedRequestsPerSlot;
	private float shareOfRetainedFormerRequests;

	private final LongAdder totalrequests = new LongAdder();
	private final ExecutorService evictionExecutor;
	private volatile Boolean asyncEviction = null;
	private final AntiDoSLogThrottler blockLogThrottler = new AntiDoSLogThrottler();

	/**
	 * The constructor gets all parameters that define the function of the Anti-DoS
	 * monitoring:
	 * 
	 * @param monitorName                   The monitors name. Used for logging
	 * @param maxCountersPerSlot            The number of active counters that can be
	 *                                      monitored within a time slot
	 * @param maxBlockedCountersPerSlot     The number of blocked counters that can be
	 *                                      monitored within a time slot
	 * @param numberOfSlots                 The number of slots to be held
	 * @param slotLength                    The length of the individual slots in seconds
	 * @param allowedRequestsPerSlot        The number of requests allowed within a slot
	 * @param shareOfRetainedFormerRequests Proportion of requests retained from previous slots
	 */
	public AntiDoSMonitor(String monitorName, int maxCountersPerSlot, int maxBlockedCountersPerSlot,
			final int numberOfSlots, int slotLength, int allowedRequestsPerSlot,
			float shareOfRetainedFormerRequests) throws IllegalArgumentException {

		if (maxCountersPerSlot < 1)
			throw new IllegalArgumentException("Parameter maxCountersPerSlot is invalid: " + maxCountersPerSlot);

		if (maxBlockedCountersPerSlot < 1)
			throw new IllegalArgumentException(
					"Parameter maxBlockedCountersPerSlot is invalid: " + maxBlockedCountersPerSlot);

		if (numberOfSlots < 1)
			throw new IllegalArgumentException("Parameter numberOfSlots is invalid: " + numberOfSlots);

		if (slotLength < 1)
			throw new IllegalArgumentException("Parameter slotLength is invalid: " + slotLength);

		if (allowedRequestsPerSlot < 1)
			throw new IllegalArgumentException(
					"Parameter allowedRequestsPerSlot is invalid: " + allowedRequestsPerSlot);

		if (shareOfRetainedFormerRequests < 0)
			throw new IllegalArgumentException(
					"Parameter shareOfRetainedFormerRequests is invalid: " + shareOfRetainedFormerRequests);
		this.monitorName = monitorName != null ? monitorName : "-";
		this.name4logging = "AntiDoSMonitor [" + this.monitorName + "]";

		this.maxCountersPerSlot = maxCountersPerSlot;
		this.maxBlockedCountersPerSlot = maxBlockedCountersPerSlot;
		this.numberOfSlots = numberOfSlots;
		this.slots = new AtomicReferenceArray<>(numberOfSlots);

		// Convert slot length in milliseconds:
		this.slotLength = slotLength * 1000;
		this.allowedRequestsPerSlot = allowedRequestsPerSlot;
		this.shareOfRetainedFormerRequests = shareOfRetainedFormerRequests;

		this.evictionExecutor = Executors.newSingleThreadExecutor(r -> {
			Thread t = new Thread(r, "AntiDoSMonitor-" + this.monitorName + "-Evictor");
			t.setDaemon(true);
			return t;
		});

		if (log.isInfoEnabled()) {
			log.info(new StringBuilder().append(name4logging).append(" created. maxCountersPerSlot=")
					.append(maxCountersPerSlot).append(", maxBlockedCountersPerSlot=").append(maxBlockedCountersPerSlot)
					.append(", numberOfSlots=").append(numberOfSlots).append(", slotLength=")
					.append(slotLength).append(", allowedRequestsPerSlot=").append(allowedRequestsPerSlot)
					.append(", shareOfRetainedFormerRequests=").append(shareOfRetainedFormerRequests).toString());
		}
	}

	/**
	 * Legacy constructor defaulting <code>maxBlockedCountersPerSlot</code> to
	 * <code>maxCountersPerSlot</code>.
	 */
	public AntiDoSMonitor(String monitorName, int maxCountersPerSlot, final int numberOfSlots, int slotLength,
			int allowedRequestsPerSlot, float shareOfRetainedFormerRequests) throws IllegalArgumentException {
		this(monitorName, maxCountersPerSlot, maxCountersPerSlot, numberOfSlots, slotLength, allowedRequestsPerSlot,
				shareOfRetainedFormerRequests);
	}

	/**
	 * This method implements the actual function of Anti-DoS monitor. It registers
	 * an increment to a specific counter (e. g. for an IP address) and, at the same
	 * time, evaluates whether the request should be blocked
	 * 
	 * @param counterName The name of the counter (e. g. an IP address)
	 * @return If <code>true</code> the request is allowed. If <code>false</code>
	 *         there had been to many accesses for this counter and the request
	 *         should be blocked
	 * @throws IllegalArgumentException If the parameter is <code>null</code> or
	 *                                  empty
	 */
	public boolean registerAndCheckRequest(String counterName) throws IllegalArgumentException {

		if (counterName == null || counterName.length() == 0)
			throw new IllegalArgumentException();

		totalrequests.increment();

		// Step 1: Provide current slot, create it if necessary:
		AntiDoSSlot slot = provideCurrentSlot();

		// Step 2: Get and increment counter
		AntiDoSCounter counter = slot.getCounter(counterName);
		counter.incrementCount();

		// Step 3: Do we have to retain counter values from previous slots?
		if (counter.getRetainedCounts() == -1) {
			if (counter.compareAndSetRetainedCounts(-1, -2)) {
				try {
					int retained = provideRetainedCountForCounter(counterName, slot.getSlotKey());
					counter.setRetainedCounts(retained);
				} catch (Exception e) {
					counter.setRetainedCounts(0);
					throw e;
				}
			}
		}

		// Step 4: Counter already locked?
		if (counter.isLocked()) {
			slot.blockCounter(counterName, counter);
			return false;
		}

		// Do we have to lock the counter now?
		if (counter.getCountCombined() > allowedRequestsPerSlot) {
			counter.lock();
			slot.blockCounter(counterName, counter);

			if (log.isInfoEnabled()) {
				boolean canLog = blockLogThrottler.shouldLog(getTimeInMillis(), suppressed -> {
					log.info(name4logging + " - [LogThrottler] Suppressed " + suppressed
							+ " block log events in the previous interval");
				});
				if (canLog) {
					log.info(name4logging + " - Counter for '" + counterName + "': " + counter.toString());
				}
			}

			return false;
		}

		return true;
	}

	/**
	 * This method fetches the desired counter from the current slot. Does not
	 * modify the status of the counter
	 * 
	 * @param counterName The name of the counter (e. g. an IP address)
	 * @return The counter object for the specified name. Returns <code>null</code>
	 *         if it does not yet exist in the current slot
	 * @throws IllegalArgumentException Thrown if parameter is empty
	 */
	public AntiDoSCounter provideCurrentCounter(String counterName) throws IllegalArgumentException {
		AntiDoSSlot slot = provideCurrentSlot();
		return slot.getCounterIfExists(counterName);
	}

	/**
	 * Checks whether a counter is currently blocked/locked in the current slot
	 * without modifying any counts or creating new counters.
	 * 
	 * @param counterName The counter name (e.g. IP address or subnet)
	 * @return <code>true</code> if the counter is currently locked in the current slot
	 * @throws IllegalArgumentException If parameter is null or empty
	 */
	public boolean isCounterBlocked(String counterName) throws IllegalArgumentException {
		if (counterName == null || counterName.isEmpty()) {
			throw new IllegalArgumentException("Counter name must not be null or empty");
		}

		AntiDoSSlot currentSlot = provideCurrentSlot();
		AntiDoSCounter counter = currentSlot.getCounterIfExists(counterName);
		return counter != null && counter.isLocked();
	}

	/**
	 * 
	 * @return Provides the current slot and creates it, if it does not yet exist
	 */
	private AntiDoSSlot provideCurrentSlot() {
		// Integer division, which provides the same result for every
		// millisecond within the slot length:
		long slotKey = getTimeInMillis() / slotLength;
		int index = (int) Math.floorMod(slotKey, numberOfSlots);

		AntiDoSSlot slot = slots.get(index);
		if (slot != null && slot.getSlotKey() == slotKey) {
			return slot;
		}

		return rotateSlot(index, slotKey);
	}

	private AntiDoSSlot rotateSlot(int index, long slotKey) {
		synchronized (slotCreationLock) {
			AntiDoSSlot slot = slots.get(index);
			if (slot != null && slot.getSlotKey() == slotKey) {
				return slot;
			}

			AntiDoSSlot newSlot = new AntiDoSSlot(monitorName, slotKey, maxCountersPerSlot,
					maxBlockedCountersPerSlot);
			newSlot.setEvictionExecutor(this.evictionExecutor);
			newSlot.setAsyncEviction(this.asyncEviction);
			slots.set(index, newSlot);
			return newSlot;
		}
	}

	/**
	 * This method provides the reference time in milliseconds from which the
	 * current slot is determined over the slot length. This implementation provides
	 * the system time. Can be overridden for testcases.
	 */
	protected long getTimeInMillis() {
		return System.currentTimeMillis();
	}

	/**
	 * This method calculates the value for
	 * {@link AntiDoSCounter#getRetainedCounts()} for a newly created counter. For
	 * this calculation the methods looks for the same counter in all other slots,
	 * sums the values in {@link AntiDoSSlot#getCounter(String)}, divides the result
	 * by the number of slots and multiplies everything with the value in
	 * <code>shareOfRetainedFormerRequests</code>
	 * 
	 * @param counterName    The name of the counter (e. g. an IP address)
	 * @param currentSlotKey The key of the current slot to exclude from calculation
	 * @throws IllegalArgumentException Thrown if parameter <code>counterName</code>
	 *                                  is empty
	 */
	private int provideRetainedCountForCounter(String counterName, long currentSlotKey) {
		if (shareOfRetainedFormerRequests == 0)
			return 0;

		int sumOfCounts = 0;
		int otherSlotsCount = 0;

		for (int i = 0; i < numberOfSlots; i++) {
			AntiDoSSlot slot = slots.get(i);
			if (slot != null) {
				long age = currentSlotKey - slot.getSlotKey();
				if (age > 0 && age < numberOfSlots) {
					otherSlotsCount++;
					AntiDoSCounter counter = slot.getCounterIfExists(counterName);
					if (counter != null)
						sumOfCounts += counter.getCount();
				}
			}
		}

		return otherSlotsCount > 0 && sumOfCounts > 0 ? Math.round(sumOfCounts * shareOfRetainedFormerRequests / otherSlotsCount) : 0;
	}

	/**
	 * 
	 * @return The total number of calls to {@link #registerAndCheckRequest(String)}
	 *         in the lifetime of this monitor instance
	 */
	public long getTotalrequests() {
		return totalrequests.sum();
	}

	/**
	 * 
	 * @return The number of currently active slots in the monitor
	 */
	public int getNumberOfActiveSlots() {
		long currentSlotKey = getTimeInMillis() / slotLength;
		int count = 0;
		for (int i = 0; i < numberOfSlots; i++) {
			AntiDoSSlot slot = slots.get(i);
			if (slot != null) {
				long age = currentSlotKey - slot.getSlotKey();
				if (age >= 0 && age < numberOfSlots) {
					count++;
				}
			}
		}
		return count;
	}

	/**
	 * Sets the asynchronous eviction strategy for all current and future slots.
	 * 
	 * @param asyncEviction <code>true</code> to force async, <code>false</code> to force sync,
	 *                      or <code>null</code> for automatic threshold based decision.
	 */
	public void setAsyncEviction(Boolean asyncEviction) {
		this.asyncEviction = asyncEviction;
		for (int i = 0; i < numberOfSlots; i++) {
			AntiDoSSlot slot = slots.get(i);
			if (slot != null) {
				slot.setAsyncEviction(asyncEviction);
			}
		}
	}

	public Boolean getAsyncEviction() {
		return this.asyncEviction;
	}

	/**
	 * @return The slot length in milliseconds.
	 */
	public int getSlotLength() {
		return this.slotLength;
	}

	/**
	 * @return Current maximum block logs emitted per second, or negative if throttling is disabled.
	 */
	public int getMaxBlockLogsPerSecond() {
		return blockLogThrottler.getMaxLogsPerSecond();
	}

	/**
	 * Sets the maximum number of block logs emitted per second.
	 * Values &lt; 0 disable throttling entirely.
	 * 
	 * @param maxBlockLogsPerSecond The limit per second, or negative to disable throttling.
	 */
	public void setMaxBlockLogsPerSecond(int maxBlockLogsPerSecond) {
		this.blockLogThrottler.setMaxLogsPerSecond(maxBlockLogsPerSecond);
	}

	/**
	 * Shuts down background executor services used by this monitor.
	 */
	public void shutdown() {
		if (evictionExecutor != null && !evictionExecutor.isShutdown()) {
			evictionExecutor.shutdownNow();
		}
	}

	/**
	 * Prints the configuration and the current state of all slots
	 */
    @Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append("#Slots: ").append(getNumberOfActiveSlots()).append("; slotLenght: ").append(slotLength)
				.append("; allowedRequestsPerSlot: ").append(allowedRequestsPerSlot).append("; maxCountersPerSlot: ")
				.append(maxCountersPerSlot).append("; maxBlockedCountersPerSlot: ")
				.append(maxBlockedCountersPerSlot).append("; shareOfRetainedFormerRequests: ")
				.append(shareOfRetainedFormerRequests).append("\n");
		sb.append("#total requests: ").append(getTotalrequests()).append("\n");

		for (int i = 0; i < numberOfSlots; i++) {
			AntiDoSSlot slot = slots.get(i);
			if (slot != null) {
				sb.append("Slot '").append(slot.getSlotKey()).append("' ").append(slot.toString()).append("\n");
			}
		}

		return sb.toString();
	}
}
