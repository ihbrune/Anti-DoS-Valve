package org.henbru.antidos;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

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

	private Map<String, AntiDoSCounter> counters = null;

	private int maxCountersPerSlot;

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

		counters = Collections
				.synchronizedMap(new LinkedHashMap<String, AntiDoSCounter>(maxCountersPerSlot, 0.75f, true) {
					private static final long serialVersionUID = 1L;

					@Override
					protected boolean removeEldestEntry(Map.Entry<String, AntiDoSCounter> eldest) {
						return size() > maxCountersPerSlot;
					}
				});
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

		boolean slotNotFullYet = counters.size() < maxCountersPerSlot;

		if (!counters.containsKey(counterName)) {
			counters.putIfAbsent(counterName, new AntiDoSCounter());

			if (log.isInfoEnabled() && slotNotFullYet && counters.size() >= maxCountersPerSlot)
				log.info(name4logging + " Counter Cache is full");
		}
		return counters.get(counterName);
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
		for (String _ip : counters.keySet()) {
			AntiDoSCounter ip = counters.get(_ip);
			if (ip.isLocked()) {
				sb.append(_ip).append(" (").append(ip.getCount()).append("|").append(ip.getRetainedCounts())
						.append(")");
				hasLockedCounters = true;
			}
		}

		if (!hasLockedCounters)
			sb.append("-");

		return sb.toString();
	}

}
