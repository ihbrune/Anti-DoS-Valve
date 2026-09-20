package org.henbru.antidos;

import java.util.Map;
import java.util.PriorityQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

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

	public static final int ASYNC_EVICTION_THRESHOLD = 500;
	public static final double HARD_CAP_RATIO = 1.2;
	public static final double LOW_WATERMARK_RATIO = 0.9;

	private final long slotKey;
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

	private volatile Boolean asyncEviction = null;
	private volatile Executor evictionExecutor = null;
	private final AtomicBoolean activeEvictionInProgress = new AtomicBoolean(false);
	private final AtomicBoolean blockedEvictionInProgress = new AtomicBoolean(false);
	private final AtomicBoolean hardCapActiveLogged = new AtomicBoolean(false);
	private final AtomicBoolean hardCapBlockedLogged = new AtomicBoolean(false);

	private record CandidateEntry(String key, AntiDoSCounter counter, long order)
			implements Comparable<CandidateEntry> {
		@Override
		public int compareTo(CandidateEntry other) {
			return Long.compare(other.order, this.order);
		}
	}

	/**
	 * @param monitorName               The monitors name. Used for logging
	 * @param slotKey                   Numeric slot sequence key
	 * @param maxCountersPerSlot        The number of active counters that can be held in the
	 *                                  slot. If exceeded, the oldest active counters are removed
	 * @param maxBlockedCountersPerSlot The number of blocked counters that can be held in the
	 *                                  slot. If exceeded, the oldest blocked counters are removed
	 */
	public AntiDoSSlot(String monitorName, long slotKey, final int maxCountersPerSlot,
			final int maxBlockedCountersPerSlot) {
		this.name4logging = "AntiDoSSlot [" + monitorName + "]";
		this.slotKey = slotKey;
		this.activeCounters = new ConcurrentHashMap<>(maxCountersPerSlot);
		this.blockedCounters = new ConcurrentHashMap<>(maxBlockedCountersPerSlot);
		this.maxCountersPerSlot = maxCountersPerSlot;
		this.maxBlockedCountersPerSlot = maxBlockedCountersPerSlot;
	}

	/**
	 * Constructor defaulting <code>maxBlockedCountersPerSlot</code> to
	 * <code>maxCountersPerSlot</code>.
	 */
	public AntiDoSSlot(String monitorName, long slotKey, final int maxCountersPerSlot) {
		this(monitorName, slotKey, maxCountersPerSlot, maxCountersPerSlot);
	}

	public long getSlotKey() {
		return slotKey;
	}

	/**
	 * Returns true if asynchronous batch eviction is used for this slot.
	 * If not explicitly configured, defaults to true when maxCountersPerSlot &gt; {@link #ASYNC_EVICTION_THRESHOLD}.
	 */
	public boolean isAsyncEvictionActive() {
		if (asyncEviction != null) {
			return asyncEviction;
		}
		return maxCountersPerSlot > ASYNC_EVICTION_THRESHOLD;
	}

	public void setAsyncEviction(Boolean asyncEviction) {
		this.asyncEviction = asyncEviction;
	}

	public Boolean getAsyncEviction() {
		return this.asyncEviction;
	}

	public void setEvictionExecutor(Executor evictionExecutor) {
		this.evictionExecutor = evictionExecutor;
	}

	public Executor getEvictionExecutor() {
		return this.evictionExecutor;
	}

	public boolean isActiveEvictionInProgress() {
		return activeEvictionInProgress.get();
	}

	public boolean isBlockedEvictionInProgress() {
		return blockedEvictionInProgress.get();
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

		// 4. Circuit Breaker / Hard-Cap check: under massive DoS floods, do not blow up memory
		int currentActiveSize = activeCounters.size();
		int hardCap = (int) Math.ceil(maxCountersPerSlot * HARD_CAP_RATIO);
		if (isAsyncEvictionActive() && currentActiveSize >= hardCap) {
			if (hardCapActiveLogged.compareAndSet(false, true) && log.isWarnEnabled()) {
				log.warn(name4logging + " Active Counter Cache hard-cap reached (" + currentActiveSize
						+ " >= " + hardCap + "). Skipping cache insertion for new counter '" + counterName
						+ "' to prevent thread exhaustion.");
			}
			triggerAsyncActiveEviction();
			AntiDoSCounter transientCounter = new AntiDoSCounter();
			transientCounter.touch(accessSequence.incrementAndGet());
			transientCounter.setRetainedCounts(0);
			return transientCounter;
		}

		// 5. New counter insertion into activeCounters
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
			if (isAsyncEvictionActive()) {
				triggerAsyncActiveEviction();
			} else if (activeCounters.size() > maxCountersPerSlot) {
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

		int currentBlockedSize = blockedCounters.size();
		int hardCap = (int) Math.ceil(maxBlockedCountersPerSlot * HARD_CAP_RATIO);
		if (isAsyncEvictionActive() && currentBlockedSize >= hardCap) {
			if (hardCapBlockedLogged.compareAndSet(false, true) && log.isWarnEnabled()) {
				log.warn(name4logging + " Blocked Counter Cache hard-cap reached (" + currentBlockedSize
						+ " >= " + hardCap + "). Keeping locked counter '" + counterName + "' in active cache.");
			}
			triggerAsyncBlockedEviction();
			return;
		}

		// Put into blocked list first, then remove from active list
		blockedCounters.put(counterName, counter);
		activeCounters.remove(counterName, counter);

		if (blockedCounters.size() >= maxBlockedCountersPerSlot) {
			if (blockedCacheFullLogged.compareAndSet(false, true) && log.isInfoEnabled()) {
				log.info(name4logging + " Blocked Counter Cache is full");
			}
			if (isAsyncEvictionActive()) {
				triggerAsyncBlockedEviction();
			} else if (blockedCounters.size() > maxBlockedCountersPerSlot) {
				evictEldestBlockedEntry();
			}
		}
	}

	/**
	 * Triggers an asynchronous batch eviction of active counters if not already in progress.
	 */
	private void triggerAsyncActiveEviction() {
		if (activeEvictionInProgress.compareAndSet(false, true)) {
			Executor exec = this.evictionExecutor != null ? this.evictionExecutor : ForkJoinPool.commonPool();
			try {
				exec.execute(this::evictActiveBatch);
			} catch (Exception e) {
				activeEvictionInProgress.set(false);
				log.warn(name4logging + " Failed to dispatch async active eviction task", e);
			}
		}
	}

	/**
	 * Triggers an asynchronous batch eviction of blocked counters if not already in progress.
	 */
	private void triggerAsyncBlockedEviction() {
		if (blockedEvictionInProgress.compareAndSet(false, true)) {
			Executor exec = this.evictionExecutor != null ? this.evictionExecutor : ForkJoinPool.commonPool();
			try {
				exec.execute(this::evictBlockedBatch);
			} catch (Exception e) {
				blockedEvictionInProgress.set(false);
				log.warn(name4logging + " Failed to dispatch async blocked eviction task", e);
			}
		}
	}

	/**
	 * Removes the least-recently-used counters from the active cache until the cache size is 
	 * at {@link #LOW_WATERMARK_RATIO}.
	 */
	private void evictActiveBatch() {
		try {
			int targetSize = (int) (maxCountersPerSlot * LOW_WATERMARK_RATIO);
			int toEvict = activeCounters.size() - targetSize;
			if (toEvict <= 0) {
				return;
			}

			PriorityQueue<CandidateEntry> maxHeap = new PriorityQueue<>(toEvict + 1);

			for (Map.Entry<String, AntiDoSCounter> entry : activeCounters.entrySet()) {
				AntiDoSCounter c = entry.getValue();
				long order = c.getAccessOrder();
				if (maxHeap.size() < toEvict) {
					maxHeap.offer(new CandidateEntry(entry.getKey(), c, order));
				} else if (order < maxHeap.peek().order()) {
					maxHeap.poll();
					maxHeap.offer(new CandidateEntry(entry.getKey(), c, order));
				}
			}

			while (!maxHeap.isEmpty()) {
				CandidateEntry cand = maxHeap.poll();
				if (cand.counter().getAccessOrder() == cand.order()) {
					activeCounters.remove(cand.key(), cand.counter());
				}
			}
		} finally {
			activeEvictionInProgress.set(false);
			hardCapActiveLogged.set(false);
		}
	}

	/**
	 * Removes the least-recently-used counters from the blocked cache until the cache size is 
	 * at {@link #LOW_WATERMARK_RATIO}.
	 */
	private void evictBlockedBatch() {
		try {
			int targetSize = (int) (maxBlockedCountersPerSlot * LOW_WATERMARK_RATIO);
			int toEvict = blockedCounters.size() - targetSize;
			if (toEvict <= 0) {
				return;
			}

			PriorityQueue<CandidateEntry> maxHeap = new PriorityQueue<>(toEvict + 1);

			for (Map.Entry<String, AntiDoSCounter> entry : blockedCounters.entrySet()) {
				AntiDoSCounter c = entry.getValue();
				long order = c.getAccessOrder();
				if (maxHeap.size() < toEvict) {
					maxHeap.offer(new CandidateEntry(entry.getKey(), c, order));
				} else if (order < maxHeap.peek().order()) {
					maxHeap.poll();
					maxHeap.offer(new CandidateEntry(entry.getKey(), c, order));
				}
			}

			while (!maxHeap.isEmpty()) {
				CandidateEntry cand = maxHeap.poll();
				if (cand.counter().getAccessOrder() == cand.order()) {
					blockedCounters.remove(cand.key(), cand.counter());
				}
			}
		} finally {
			blockedEvictionInProgress.set(false);
			hardCapBlockedLogged.set(false);
		}
	}

	private void evictEldestActiveEntry() {
		activeEvictionLock.lock();
		try {
			while (activeCounters.size() > maxCountersPerSlot) {
				String oldestKey = null;
				AntiDoSCounter oldestCounter = null;
				long oldestOrder = Long.MAX_VALUE;

				for (Map.Entry<String, AntiDoSCounter> entry : activeCounters.entrySet()) {
					long order = entry.getValue().getAccessOrder();
					if (order < oldestOrder) {
						oldestOrder = order;
						oldestKey = entry.getKey();
						oldestCounter = entry.getValue();
					}
				}

				if (oldestKey != null && oldestCounter != null) {
					activeCounters.remove(oldestKey, oldestCounter);
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
				AntiDoSCounter oldestCounter = null;
				long oldestOrder = Long.MAX_VALUE;

				for (Map.Entry<String, AntiDoSCounter> entry : blockedCounters.entrySet()) {
					long order = entry.getValue().getAccessOrder();
					if (order < oldestOrder) {
						oldestOrder = order;
						oldestKey = entry.getKey();
						oldestCounter = entry.getValue();
					}
				}

				if (oldestKey != null && oldestCounter != null) {
					blockedCounters.remove(oldestKey, oldestCounter);
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
