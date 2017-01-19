package org.henbru.antidos;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Instances of this class are used to count occasions of similar events. For
 * example requests coming form the same IP address
 * 
 * @author Henning
 *
 */
public class AntiDoSCounter {

	private final AtomicInteger count = new AtomicInteger(0);

	private final AtomicInteger retainedCounts = new AtomicInteger(-1);

	private boolean locked = false;

	/**
	 * 
	 * @return This counter is to be used for counting current accesses
	 */
	public AtomicInteger getCount() {
		return count;
	}

	/**
	 * 
	 * @return This counter can be used to store access numbers taken from
	 *         previous measurement intervals (slots). It's initial value is -1,
	 *         in this way a distinction can be made if an initialization
	 *         already took place
	 */
	public AtomicInteger getRetainedCounts() {
		return retainedCounts;
	}

	/**
	 * 
	 * @return The sum of {@link #getCount()} and {@link #getRetainedCounts()}
	 */
	public int getCountCombined() {
		int countCurrent = count.get();
		int countRetained = retainedCounts.get();

		return countRetained < 0 ? countCurrent : countCurrent + countRetained;
	}

	/**
	 * 
	 * @return Query of the lock status. If the default is <code>false</code>,
	 *         you can set it to <code>true</code> using {@link #lock()}
	 * 
	 */
	public boolean isLocked() {
		return locked;
	}

	/**
	 * Using this method, the counter can be flagged as locked
	 */
	public void lock() {
		this.locked = true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append("Count:").append(getCount()).append(" Retained:")
				.append(getRetainedCounts()).append(" Locked:")
				.append(locked ? "yes" : "no");

		return sb.toString();
	}

}
