package org.henbru.antidos;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Consumer;

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
 * Rate limiter for log events to prevent disk I/O saturation and thread contention
 * during high-volume DoS attacks.
 * 
 * @author Henning
 */
public class AntiDoSLogThrottler {

	public static final int DEFAULT_MAX_LOGS_PER_SECOND = 20;

	private volatile int maxLogsPerSecond;
	private final AtomicInteger logsInCurrentWindow = new AtomicInteger(0);
	private final LongAdder suppressedCount = new LongAdder();
	private final AtomicLong currentWindowSecond = new AtomicLong(-1);

	public AntiDoSLogThrottler() {
		this(DEFAULT_MAX_LOGS_PER_SECOND);
	}

	public AntiDoSLogThrottler(int maxLogsPerSecond) {
		this.maxLogsPerSecond = maxLogsPerSecond;
	}

	public int getMaxLogsPerSecond() {
		return maxLogsPerSecond;
	}

	/**
	 * Sets the maximum number of log messages emitted per second.
	 * Values &lt; 0 disable throttling entirely (all logs emitted).
	 * 
	 * @param maxLogsPerSecond Limit per second, or negative to disable throttling.
	 */
	public void setMaxLogsPerSecond(int maxLogsPerSecond) {
		this.maxLogsPerSecond = maxLogsPerSecond;
	}

	/**
	 * Checks whether the current log event should be emitted.
	 * 
	 * @param currentTimeMillis Current time in milliseconds
	 * @param onSuppressedSummary Callback invoked when transitioning to a new window if logs were suppressed
	 * @return true if the log event is allowed; false if throttled
	 */
	public boolean shouldLog(long currentTimeMillis, Consumer<Long> onSuppressedSummary) {
		int limit = this.maxLogsPerSecond;
		if (limit < 0) {
			// Throttling disabled
			return true;
		}
		long nowSec = currentTimeMillis / 1000;
		long oldSec = currentWindowSecond.get();

		if (nowSec != oldSec) {
			if (currentWindowSecond.compareAndSet(oldSec, nowSec)) {
				logsInCurrentWindow.set(0);
				long suppressed = suppressedCount.sumThenReset();
				if (suppressed > 0 && onSuppressedSummary != null) {
					onSuppressedSummary.accept(suppressed);
				}
			}
		}

		if (limit == 0) {
			suppressedCount.increment();
			return false;
		}

		int current = logsInCurrentWindow.get();
		while (current < limit) {
			if (logsInCurrentWindow.compareAndSet(current, current + 1)) {
				return true;
			}
			current = logsInCurrentWindow.get();
		}

		suppressedCount.increment();
		return false;
	}

	/**
	 * Convenience method evaluating against System.currentTimeMillis().
	 */
	public boolean shouldLog(Consumer<Long> onSuppressedSummary) {
		return shouldLog(System.currentTimeMillis(), onSuppressedSummary);
	}
}
