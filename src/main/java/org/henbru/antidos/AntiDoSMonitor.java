package org.henbru.antidos;

import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Copyright 2017 Henning Brune
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
	private int numberOfSlots;
	private final ConcurrentNavigableMap<Long, AntiDoSSlot> slots;
	private int slotLength;
	private int allowedRequestsPerSlot;
	private float shareOfRetainedFormerRequests;

	private final AtomicInteger totalrequests = new AtomicInteger(0);
	private final ExecutorService evictionExecutor;
	private volatile Boolean asyncEviction = null;

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
		this.slots = new ConcurrentSkipListMap<>();

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

		totalrequests.addAndGet(1);

		// Step 1: Provide current slot, create it if necessary:
		AntiDoSSlot slot = provideCurrentSlot();

		// Step 2: Get and increment counter
		AntiDoSCounter counter = slot.getCounter(counterName);
		counter.getCount().addAndGet(1);

		// Step 3: Do we have to retain counter values from previous slots?
		if (counter.getRetainedCounts().get() == -1) {
			int retained = provideRetainedCountForCounter(counterName, slot.getKey());
			counter.getRetainedCounts().compareAndSet(-1, retained);
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

			if (log.isInfoEnabled())
				log.info(name4logging + " - Counter for '" + counterName + "': " + counter.toString());

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
	 * 
	 * @return Provides the current slot and creates it, if it does not yet exist
	 */
	private AntiDoSSlot provideCurrentSlot() {
		// Integer division, which provides the same result for every
		// millisecond within the slot length:
		long slotKey = getTimeInMillis() / slotLength;

		AntiDoSSlot slot = slots.computeIfAbsent(slotKey, k -> {
			AntiDoSSlot s = new AntiDoSSlot(monitorName, String.valueOf(k), maxCountersPerSlot,
					maxBlockedCountersPerSlot);
			s.setEvictionExecutor(this.evictionExecutor);
			s.setAsyncEviction(this.asyncEviction);
			return s;
		});
		pruneOldSlots();
		return slot;
	}

	private void pruneOldSlots() {
		while (slots.size() > numberOfSlots) {
			slots.pollFirstEntry();
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
	 * @param counterName         The name of the counter (e. g. an IP address)
	 * @param keyForSlotToExclude The key (@see {@link AntiDoSSlot#getKey()}) of the
	 *                            slot whos counters are excluded from the
	 *                            calculation. This will be the key of the current
	 *                            slot
	 * @throws IllegalArgumentException Thrown if parameter <code>counterName</code>
	 *                                  is empty
	 */
	private int provideRetainedCountForCounter(String counterName, String keyForSlotToExclude) {
		if (shareOfRetainedFormerRequests == 0)
			return 0;

		int sumOfCounts = 0;
		int otherSlotsCount = 0;

		for (AntiDoSSlot slot : slots.values()) {
			// Ignore count from excluded slot:
			if (slot.getKey().equals(keyForSlotToExclude))
				continue;

			otherSlotsCount++;

			AntiDoSCounter counter = slot.getCounterIfExists(counterName);
			if (counter != null)
				sumOfCounts += counter.getCount().get();
		}

		return otherSlotsCount > 0 && sumOfCounts > 0 ? Math.round(sumOfCounts * shareOfRetainedFormerRequests / otherSlotsCount) : 0;
	}

	/**
	 * 
	 * @return The total number of calls to {@link #registerAndCheckRequest(String)}
	 *         in the lifetime of this monitor instance
	 */
	public int getTotalrequests() {
		return totalrequests.get();
	}

	/**
	 * 
	 * @return The number of currently active slots in the monitor
	 */
	public int getNumberOfActiveSlots() {
		return slots.size();
	}

	/**
	 * Sets the asynchronous eviction strategy for all current and future slots.
	 * 
	 * @param asyncEviction <code>true</code> to force async, <code>false</code> to force sync,
	 *                      or <code>null</code> for automatic threshold based decision.
	 */
	public void setAsyncEviction(Boolean asyncEviction) {
		this.asyncEviction = asyncEviction;
		for (AntiDoSSlot slot : slots.values()) {
			slot.setAsyncEviction(asyncEviction);
		}
	}

	/**
	 * @return Current asyncEviction setting, or <code>null</code> if automatic threshold is active.
	 */
	public Boolean getAsyncEviction() {
		return this.asyncEviction;
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

		sb.append("#Slots: ").append(slots.size()).append("; slotLenght: ").append(slotLength)
				.append("; allowedRequestsPerSlot: ").append(allowedRequestsPerSlot).append("; maxCountersPerSlot: ")
				.append(maxCountersPerSlot).append("; maxBlockedCountersPerSlot: ")
				.append(maxBlockedCountersPerSlot).append("; shareOfRetainedFormerRequests: ")
				.append(shareOfRetainedFormerRequests).append("\n");
		sb.append("#total requests: ").append(getTotalrequests()).append("\n");

		for (AntiDoSSlot slot : slots.values()) {
			sb.append("Slot '").append(slot.getKey()).append("' ").append(slot.toString()).append("\n");
		}

		return sb.toString();
	}
}
