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
	private static final VarHandle CARDINALITY_TRACKER;
	private static final VarHandle RETURNING_COUNT;
	private static final VarHandle SAMPLE_REQUEST;

	/**
	 * Compact, immutable snapshot of an offending client request captured upon rate-limit blocking.
	 * All string fields are strictly bounded and sanitized.
	 */
	public record SampleRequest(String method, String uri, String userAgent) {}

	static {
		try {
			MethodHandles.Lookup l = MethodHandles.lookup();
			COUNT = l.findVarHandle(AntiDoSCounter.class, "count", int.class);
			RETAINED_COUNTS = l.findVarHandle(AntiDoSCounter.class, "retainedCounts", int.class);
			ACCESS_ORDER = l.findVarHandle(AntiDoSCounter.class, "accessOrder", long.class);
			CARDINALITY_TRACKER = l.findVarHandle(AntiDoSCounter.class, "cardinalityTracker", AntiDoSCardinalityBitSet.class);
			RETURNING_COUNT = l.findVarHandle(AntiDoSCounter.class, "returningCount", int.class);
			SAMPLE_REQUEST = l.findVarHandle(AntiDoSCounter.class, "sampleRequest", SampleRequest.class);
		} catch (ReflectiveOperationException e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private volatile int count = 0;
	private volatile int retainedCounts = -1;
	private volatile long accessOrder = 0;
	private volatile boolean locked = false;
	private volatile AntiDoSCardinalityBitSet cardinalityTracker = null;
	private volatile int returningCount = 0;
	private volatile SampleRequest sampleRequest = null;

	/**
	 * Updates the access order timestamp to current System.nanoTime() for LRU recency tracking.
	 */
	public void touch() {
		touch(System.nanoTime());
	}

	/**
	 * Updates the access order sequence for LRU recency tracking.
	 * 
	 * @param order A monotonic timestamp or sequence number
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
	 * Atomically increments the returning visitor count by 1.
	 * 
	 * @return The updated returning visitor count
	 */
	public int incrementReturningCount() {
		return (int) RETURNING_COUNT.getAndAdd(this, 1) + 1;
	}

	/**
	 * Atomically adds the given delta to the returning visitor count.
	 * 
	 * @param delta The value to add
	 * @return The updated returning visitor count
	 */
	public int addAndGetReturningCount(int delta) {
		return (int) RETURNING_COUNT.getAndAdd(this, delta) + delta;
	}

	/**
	 * @return The current returning visitor count
	 */
	public int getReturningCount() {
		return returningCount;
	}

	/**
	 * Sets the returning visitor count directly to the specified value.
	 * 
	 * @param value The new returning visitor count
	 */
	public void setReturningCount(int value) {
		RETURNING_COUNT.setVolatile(this, value);
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

	/**
	 * Registers a client IP into the subnet cardinality bitset.
	 * Instantiates the bitset lazily on first access.
	 * 
	 * @param ipv4Bytes Parsed 4-byte array if IPv4 literal, or null otherwise
	 * @param ip        Raw IP string
	 * @param v4Mask    IPv4 subnet prefix length
	 * @param v6Mask    IPv6 subnet prefix length
	 */
	public void registerClientIp(byte[] ipv4Bytes, String ip, int v4Mask, int v6Mask) {
		AntiDoSCardinalityBitSet tracker = this.cardinalityTracker;
		if (tracker == null) {
			AntiDoSCardinalityBitSet newTracker = new AntiDoSCardinalityBitSet();
			CARDINALITY_TRACKER.compareAndSet(this, null, newTracker);
			tracker = (AntiDoSCardinalityBitSet) CARDINALITY_TRACKER.getVolatile(this);
		}
		tracker.register(ipv4Bytes, ip, v4Mask, v6Mask);
	}

	/**
	 * @return The number of distinct client IP addresses observed for this counter.
	 *         Defaults to 1 if not an aggregated subnet or no tracker instantiated.
	 */
	public int getDistinctClients() {
		AntiDoSCardinalityBitSet tracker = this.cardinalityTracker;
		return tracker != null ? tracker.getDistinctCount() : 1;
	}

	/**
	 * @return true if cardinality tracking was active and has recorded distinct client IPs.
	 */
	public boolean hasCardinalityTracker() {
		return this.cardinalityTracker != null;
	}

	/**
	 * @return The captured request sample snapshot, or <code>null</code> if none recorded.
	 */
	public SampleRequest getSample() {
		return this.sampleRequest;
	}

	/**
	 * Atomically captures an offending request sample if no sample has been recorded yet.
	 * All fields are strictly sanitized and length-bounded to prevent memory bloat or injection.
	 * Query parameters are explicitly stripped for privacy/GDPR compliance.
	 *
	 * @param method    HTTP method (e.g. "POST")
	 * @param uri       Request URI path (query string stripped, max 256 chars)
	 * @param userAgent User-Agent header (max 128 chars)
	 * @return true if the sample was successfully captured, false if a sample already exists
	 */
	public boolean recordSampleIfAbsent(String method, String uri, String userAgent) {
		if (this.sampleRequest != null) {
			return false;
		}
		String cleanMethod = sanitizeMethod(method);
		String cleanUri = sanitizeUri(uri);
		String cleanUserAgent = sanitizeUserAgent(userAgent);
		if (cleanMethod == null && cleanUri == null) {
			return false;
		}
		SampleRequest sample = new SampleRequest(cleanMethod, cleanUri, cleanUserAgent);
		return SAMPLE_REQUEST.compareAndSet(this, null, sample);
	}

	static String sanitizeMethod(String method) {
		if (method == null || method.isBlank()) {
			return null;
		}
		String trimmed = method.trim().toUpperCase(java.util.Locale.ROOT);
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < trimmed.length() && sb.length() < 10; i++) {
			char c = trimmed.charAt(i);
			if (c >= 'A' && c <= 'Z') {
				sb.append(c);
			}
		}
		return sb.length() > 0 ? sb.toString() : null;
	}

	static String sanitizeUri(String uri) {
		if (uri == null || uri.isBlank()) {
			return null;
		}
		String clean = uri.trim();
		int qIdx = clean.indexOf('?');
		if (qIdx >= 0) {
			clean = clean.substring(0, qIdx);
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < clean.length() && sb.length() < 256; i++) {
			char c = clean.charAt(i);
			if (c >= 32 && c <= 126) {
				sb.append(c);
			}
		}
		return sb.length() > 0 ? sb.toString() : null;
	}

	static String sanitizeUserAgent(String ua) {
		if (ua == null || ua.isBlank()) {
			return null;
		}
		String clean = ua.trim();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < clean.length() && sb.length() < 128; i++) {
			char c = clean.charAt(i);
			if (c >= 32 && c <= 126) {
				sb.append(c);
			}
		}
		return sb.length() > 0 ? sb.toString() : null;
	}

	@Override
	public String toString() {
		return "Count:" + getCount() + " Retained:" + getRetainedCounts() + " Locked:" + (locked ? "yes" : "no")
				+ (cardinalityTracker != null ? " DistinctClients:" + getDistinctClients() : "")
				+ (returningCount > 0 ? " Returning:" + returningCount : "")
				+ (sampleRequest != null ? " Sample:" + sampleRequest.method() + " " + sampleRequest.uri() : "");
	}
}
