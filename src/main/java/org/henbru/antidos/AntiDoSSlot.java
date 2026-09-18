package org.henbru.antidos;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

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
 * This class implements the slots within the Anti-DoS Monitor. It manages a set
 * of counters that can, for example, represent the accesses of individual IP
 * addresses. The maximum number of managed counters is limited by the parameter
 * in the constructor
 * 
 * @author Henning
 *
 */
public class AntiDoSSlot {
	private static final Log log = LogFactory.getLog(AntiDoSValve.ANTIDOS_LOGGER_NAME);

	private String key;
	private String name4logging;

	private final ConcurrentHashMap<String, AntiDoSCounter> counters;

	private int maxCountersPerSlot;
	private final AtomicLong accessSequence = new AtomicLong(0);
	private final AtomicBoolean cacheFullLogged = new AtomicBoolean(false);
	private final ReentrantLock evictionLock = new ReentrantLock();

	/**
	 * @param monitorName        The monitors name. Used for logging
	 * @param key                This attribute is used to name a slot. It should be
	 *                           unique for every slot used in a
	 *                           {@link AntiDoSMonitor} instance
	 * 
	 * @param maxCountersPerSlot The number of counters that can be held in the
	 *                           slot. If the number is exceeded, the counters that
	 *                           have not been accessed the longest are removed
	 * @throws IllegalArgumentException Thrown if <code>key</code> is empty
	 */
	public AntiDoSSlot(String monitorName, String key, final int maxCountersPerSlot) throws IllegalArgumentException {
		if (key == null || key.length() == 0)
			throw new IllegalArgumentException();

		this.name4logging = "AntiDoSSlot [" + monitorName + "]";
		this.key = key;
		this.counters = new ConcurrentHashMap<>(maxCountersPerSlot);
		this.maxCountersPerSlot = maxCountersPerSlot;
	}

	/**
	 * @param counterName The name of the counter (e. g. an IP address)
	 * @return Provides the counter object for a specified name and creates it, if
	 *         it does not yet exist
	 * @throws IllegalArgumentException Thrown if parameter is empty
	 */
	public AntiDoSCounter getCounter(String counterName) throws IllegalArgumentException {
		if (counterName == null || counterName.length() == 0)
			throw new IllegalArgumentException();

		// Fast path for existing counters (lock-free)
		AntiDoSCounter existing = counters.get(counterName);
		if (existing != null) {
			existing.touch(accessSequence.incrementAndGet());
			return existing;
		}

		// New counter insertion
		AntiDoSCounter newCounter = new AntiDoSCounter();
		newCounter.touch(accessSequence.incrementAndGet());
		AntiDoSCounter previous = counters.putIfAbsent(counterName, newCounter);
		if (previous != null) {
			previous.touch(accessSequence.incrementAndGet());
			return previous;
		}

		// Check if capacity was reached/exceeded
		if (counters.size() >= maxCountersPerSlot) {
			if (cacheFullLogged.compareAndSet(false, true) && log.isInfoEnabled()) {
				log.info(name4logging + " Counter Cache is full");
			}
			if (counters.size() > maxCountersPerSlot) {
				evictEldestEntry();
			}
		}

		return newCounter;
	}

	private void evictEldestEntry() {
		evictionLock.lock();
		try {
			while (counters.size() > maxCountersPerSlot) {
				String oldestKey = null;
				long oldestOrder = Long.MAX_VALUE;

				for (Map.Entry<String, AntiDoSCounter> entry : counters.entrySet()) {
					long order = entry.getValue().getAccessOrder();
					if (order < oldestOrder) {
						oldestOrder = order;
						oldestKey = entry.getKey();
					}
				}

				if (oldestKey != null) {
					counters.remove(oldestKey);
				} else {
					break;
				}
			}
		} finally {
			evictionLock.unlock();
		}
	}

	/**
	 * @param counterName The name of the counter (e. g. an IP address)
	 * @return Provides the counter object for the specified name. Returns
	 *         <code>null</code> if it does not yet exist
	 * @throws IllegalArgumentException Thrown if parameter is empty
	 */
	public AntiDoSCounter getCounterIfExists(String counterName) throws IllegalArgumentException {
		if (counterName == null || counterName.length() == 0)
			throw new IllegalArgumentException();

		return counters.get(counterName);
	}

	public String getKey() {
		return key;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append("#Counters: ").append(counters.size()).append(" Locked: ");

		boolean hasLockedCounters = false;
		for (Map.Entry<String, AntiDoSCounter> entry : counters.entrySet()) {
			AntiDoSCounter ip = entry.getValue();
			if (ip.isLocked()) {
				sb.append(entry.getKey()).append(" (").append(ip.getCount()).append("|").append(ip.getRetainedCounts())
						.append(")");
				hasLockedCounters = true;
			}
		}

		if (!hasLockedCounters)
			sb.append("-");

		return sb.toString();
	}

}
