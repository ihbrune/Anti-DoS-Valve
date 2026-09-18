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

	private final ConcurrentHashMap<String, AntiDoSCounter> activeCounters;
	private final ConcurrentHashMap<String, AntiDoSCounter> blockedCounters;

	private int maxCountersPerSlot;
	private int maxBlockedCountersPerSlot;
	private final AtomicLong accessSequence = new AtomicLong(0);
	private final AtomicBoolean activeCacheFullLogged = new AtomicBoolean(false);
	private final AtomicBoolean blockedCacheFullLogged = new AtomicBoolean(false);
	private final ReentrantLock activeEvictionLock = new ReentrantLock();
	private final ReentrantLock blockedEvictionLock = new ReentrantLock();

	/**
	 * @param monitorName               The monitors name. Used for logging
	 * @param key                       This attribute is used to name a slot. It should be
	 *                                  unique for every slot used in a
	 *                                  {@link AntiDoSMonitor} instance
	 * @param maxCountersPerSlot        The number of active counters that can be held in the
	 *                                  slot. If exceeded, the oldest active counters are removed
	 * @param maxBlockedCountersPerSlot The number of blocked counters that can be held in the
	 *                                  slot. If exceeded, the oldest blocked counters are removed
	 * @throws IllegalArgumentException Thrown if <code>key</code> is empty
	 */
	public AntiDoSSlot(String monitorName, String key, final int maxCountersPerSlot, final int maxBlockedCountersPerSlot)
			throws IllegalArgumentException {
		if (key == null || key.length() == 0)
			throw new IllegalArgumentException();

		this.name4logging = "AntiDoSSlot [" + monitorName + "]";
		this.key = key;
		this.activeCounters = new ConcurrentHashMap<>(maxCountersPerSlot);
		this.blockedCounters = new ConcurrentHashMap<>(maxBlockedCountersPerSlot);
		this.maxCountersPerSlot = maxCountersPerSlot;
		this.maxBlockedCountersPerSlot = maxBlockedCountersPerSlot;
	}

	/**
	 * Legacy constructor defaulting <code>maxBlockedCountersPerSlot</code> to
	 * <code>maxCountersPerSlot</code>.
	 */
	public AntiDoSSlot(String monitorName, String key, final int maxCountersPerSlot) throws IllegalArgumentException {
		this(monitorName, key, maxCountersPerSlot, maxCountersPerSlot);
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

		// 1. Check blocked counters (fast path for already blocked IPs)
		AntiDoSCounter blocked = blockedCounters.get(counterName);
		if (blocked != null) {
			blocked.touch(accessSequence.incrementAndGet());
			return blocked;
		}

		// 2. Check active counters (fast path for non-blocked IPs)
		AntiDoSCounter active = activeCounters.get(counterName);
		if (active != null) {
			active.touch(accessSequence.incrementAndGet());
			return active;
		}

		// 3. Re-check blockedCounters in case concurrent promotion happened
		blocked = blockedCounters.get(counterName);
		if (blocked != null) {
			blocked.touch(accessSequence.incrementAndGet());
			return blocked;
		}

		// 4. New counter insertion into activeCounters
		AntiDoSCounter newCounter = new AntiDoSCounter();
		newCounter.touch(accessSequence.incrementAndGet());
		AntiDoSCounter previous = activeCounters.putIfAbsent(counterName, newCounter);
		if (previous != null) {
			previous.touch(accessSequence.incrementAndGet());
			return previous;
		}

		// Check if capacity was reached/exceeded for active counters
		if (activeCounters.size() >= maxCountersPerSlot) {
			if (activeCacheFullLogged.compareAndSet(false, true) && log.isInfoEnabled()) {
				log.info(name4logging + " Counter Cache is full");
			}
			if (activeCounters.size() > maxCountersPerSlot) {
				evictEldestActiveEntry();
			}
		}

		return newCounter;
	}

	/**
	 * Moves a counter to the blocked list and removes it from the active list.
	 * 
	 * @param counterName The name of the counter (e.g. IP address)
	 * @param counter     The counter instance that has been locked
	 */
	public void blockCounter(String counterName, AntiDoSCounter counter) {
		if (counterName == null || counter == null)
			return;

		// Put into blocked list first, then remove from active list
		blockedCounters.put(counterName, counter);
		activeCounters.remove(counterName, counter);

		if (blockedCounters.size() >= maxBlockedCountersPerSlot) {
			if (blockedCacheFullLogged.compareAndSet(false, true) && log.isInfoEnabled()) {
				log.info(name4logging + " Blocked Counter Cache is full");
			}
			if (blockedCounters.size() > maxBlockedCountersPerSlot) {
				evictEldestBlockedEntry();
			}
		}
	}

	private void evictEldestActiveEntry() {
		activeEvictionLock.lock();
		try {
			while (activeCounters.size() > maxCountersPerSlot) {
				String oldestKey = null;
				long oldestOrder = Long.MAX_VALUE;

				for (Map.Entry<String, AntiDoSCounter> entry : activeCounters.entrySet()) {
					long order = entry.getValue().getAccessOrder();
					if (order < oldestOrder) {
						oldestOrder = order;
						oldestKey = entry.getKey();
					}
				}

				if (oldestKey != null) {
					activeCounters.remove(oldestKey);
				} else {
					break;
				}
			}
		} finally {
			activeEvictionLock.unlock();
		}
	}

	private void evictEldestBlockedEntry() {
		blockedEvictionLock.lock();
		try {
			while (blockedCounters.size() > maxBlockedCountersPerSlot) {
				String oldestKey = null;
				long oldestOrder = Long.MAX_VALUE;

				for (Map.Entry<String, AntiDoSCounter> entry : blockedCounters.entrySet()) {
					long order = entry.getValue().getAccessOrder();
					if (order < oldestOrder) {
						oldestOrder = order;
						oldestKey = entry.getKey();
					}
				}

				if (oldestKey != null) {
					blockedCounters.remove(oldestKey);
				} else {
					break;
				}
			}
		} finally {
			blockedEvictionLock.unlock();
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

		AntiDoSCounter blocked = blockedCounters.get(counterName);
		if (blocked != null) {
			return blocked;
		}
		return activeCounters.get(counterName);
	}

	public String getKey() {
		return key;
	}

	public int getActiveCounterCount() {
		return activeCounters.size();
	}

	public int getBlockedCounterCount() {
		return blockedCounters.size();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append("#Counters: ").append(activeCounters.size() + blockedCounters.size())
				.append(" (#Active: ").append(activeCounters.size())
				.append(" #Blocked: ").append(blockedCounters.size())
				.append(") Locked: ");

		boolean hasLockedCounters = false;
		for (Map.Entry<String, AntiDoSCounter> entry : blockedCounters.entrySet()) {
			AntiDoSCounter ip = entry.getValue();
			sb.append(entry.getKey()).append(" (").append(ip.getCount()).append("|").append(ip.getRetainedCounts())
					.append(")");
			hasLockedCounters = true;
		}

		if (!hasLockedCounters)
			sb.append("-");

		return sb.toString();
	}

}
