package org.henbru.antidos;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLongArray;

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
 * High-speed, zero-allocation, bounded in-memory session cache for tracking
 * authenticated login cookies across one or more {@link AntiDoSValve} instances
 * in the same server.
 * <p>
 * <strong>Design Rationale (Salted 64-Bit Fast Hash + Primitive Open-Addressing):</strong>
 * <ol>
 *   <li><strong>Zero-Allocation 64-Bit Hashing:</strong> Rather than allocating {@code byte[]}
 *       buffers and computing cryptographic SHA-256 digests on every incoming HTTP request,
 *       cookie values are hashed directly over their UTF-16 characters into a primitive 64-bit
 *       {@code long} using a per-JVM random 128-bit seed ({@link SecureRandom}) and
 *       SplitMix64 / MurmurHash3-64 avalanche mixing.</li>
 *   <li><strong>Zero-Boxing Open-Addressing Storage (~16 Bytes / Session):</strong> Instead of
 *       {@code ConcurrentHashMap<Long, Long>} (which boxes primitive {@code long} keys and
 *       timestamps into {@code java.lang.Long} objects and allocates {@code Node} wrappers at
 *       ~80&ndash;96 bytes per entry), this cache stores interleaved {@code [hash, expiresAt]}
 *       primitive {@code long} pairs inside a flat {@link AtomicLongArray} with bounded linear
 *       probing ({@link #MAX_PROBE_DISTANCE} slots). Lookups, insertions, and evictions are
 *       100% allocation-free and L1/L2 CPU-cache friendly.</li>
 *   <li><strong>Lock-Free Local TTL Eviction:</strong> When all slots within a bounded probe
 *       window are occupied by active sessions, insertion overwrites the slot in that window
 *       whose {@code expiresAt} timestamp is closest to expiring, eliminating global eviction
 *       locks and priority queues.</li>
 * </ol>
 * 
 * @author Henning
 */
public final class AntiDoSAuthSessionCache {

	public static final int DEFAULT_MAX_CAPACITY = 50_000;
	public static final int DEFAULT_SESSION_TTL_SECONDS = 900;

	/**
	 * Maximum number of consecutive slots inspected during linear probing.
	 * 16 slots = 32 longs = 256 bytes (4 contiguous 64-byte CPU cache lines).
	 */
	static final int MAX_PROBE_DISTANCE = 16;

	/**
	 * Sentinel value representing an empty slot in the open-addressing table.
	 */
	private static final long EMPTY_HASH = 0L;

	private static final long HASH_SEED_0;
	private static final long HASH_SEED_1;

	static {
		SecureRandom sr = new SecureRandom();
		HASH_SEED_0 = sr.nextLong();
		HASH_SEED_1 = sr.nextLong();
	}

	/**
	 * Immutable snapshot of the backing primitive table and its capacity parameters.
	 */
	private record TableState(AtomicLongArray table, int capacity, int probeLimit) {
		TableState(int capacity) {
			this(new AtomicLongArray(capacity * 2), capacity, Math.min(MAX_PROBE_DISTANCE, capacity));
		}
	}

	private volatile TableState state;

	public AntiDoSAuthSessionCache() {
		this(DEFAULT_MAX_CAPACITY);
	}

	public AntiDoSAuthSessionCache(int maxCapacity) {
		if (maxCapacity < 1) {
			throw new IllegalArgumentException("maxCapacity must be positive: " + maxCapacity);
		}
		this.state = new TableState(maxCapacity);
	}

	/**
	 * Computes a keyed 64-bit hash over the characters of the given token value
	 * without allocating intermediate byte or character arrays.
	 * <p>
	 * Non-empty inputs never return {@code 0L} (which is reserved as {@link #EMPTY_HASH}).
	 *
	 * @param tokenValue The raw cookie or token value
	 * @return Non-zero 64-bit keyed hash, or {@code 0L} if null/empty
	 */
	public static long computeHash(String tokenValue) {
		if (tokenValue == null || tokenValue.isEmpty()) {
			return EMPTY_HASH;
		}
		int len = tokenValue.length();
		long h = HASH_SEED_0 ^ (len * 0x9E3779B97F4A7C15L);
		for (int i = 0; i < len; i++) {
			h ^= tokenValue.charAt(i);
			h *= 0xBF58476D1CE4E5B9L;
			h ^= (h >>> 31);
		}
		h ^= HASH_SEED_1;
		h = (h ^ (h >>> 30)) * 0xBF58476D1CE4E5B9L;
		h = (h ^ (h >>> 27)) * 0x94D049BB133111EBL;
		long res = h ^ (h >>> 31);
		return res == EMPTY_HASH ? 1L : res;
	}

	private static int startSlot(long hash, int capacity) {
		return (int) Long.remainderUnsigned(hash, capacity);
	}

	/**
	 * Checks whether the given cookie/token value corresponds to an active,
	 * non-expired authenticated session. If an entry is found but expired, it is
	 * lazily cleared in place without any heap allocations.
	 *
	 * @param tokenValue The raw cookie value from the HTTP request
	 * @param nowMillis  Current timestamp in milliseconds
	 * @return {@code true} if the token is known and not expired
	 */
	public boolean isValidSession(String tokenValue, long nowMillis) {
		long hash = computeHash(tokenValue);
		if (hash == EMPTY_HASH) {
			return false;
		}

		TableState current = this.state;
		AtomicLongArray table = current.table;
		int capacity = current.capacity;
		int probeLimit = current.probeLimit;
		int slot = startSlot(hash, capacity);

		for (int step = 0; step < probeLimit; step++) {
			int idx = slot << 1;
			long slotHash = table.get(idx);
			if (slotHash == hash) {
				long expiresAt = table.get(idx + 1);
				if (expiresAt > 0L && nowMillis <= expiresAt) {
					return true;
				}
				if (expiresAt > 0L && nowMillis > expiresAt) {
					// Lazy expiration cleanup
					if (table.compareAndSet(idx + 1, expiresAt, 0L)) {
						table.compareAndSet(idx, hash, EMPTY_HASH);
					}
				}
				return false;
			}
			if (++slot == capacity) {
				slot = 0;
			}
		}
		return false;
	}

	/**
	 * Registers a newly issued or refreshed authentication token in the cache.
	 * Runs completely lock-free and allocation-free using bounded linear probing
	 * and local earliest-expiration replacement.
	 *
	 * @param tokenValue The raw cookie value
	 * @param ttlMillis  Time-to-live in milliseconds (must be &gt; 0)
	 * @param nowMillis  Current timestamp in milliseconds
	 */
	public void registerSession(String tokenValue, long ttlMillis, long nowMillis) {
		if (ttlMillis <= 0) {
			return;
		}
		long hash = computeHash(tokenValue);
		if (hash == EMPTY_HASH) {
			return;
		}
		long expiresAt = nowMillis + ttlMillis;

		TableState current = this.state;
		AtomicLongArray table = current.table;
		int capacity = current.capacity;
		int probeLimit = current.probeLimit;
		int baseSlot = startSlot(hash, capacity);

		// Retry loop in case of rare concurrent CAS contention on the chosen slot
		for (int attempt = 0; attempt < 4; attempt++) {
			int freeIdx = -1;
			long freeExpectedHash = EMPTY_HASH;

			int earliestIdx = -1;
			long earliestHash = EMPTY_HASH;
			long earliestExpiry = Long.MAX_VALUE;

			int slot = baseSlot;
			for (int step = 0; step < probeLimit; step++) {
				int idx = slot << 1;
				long slotHash = table.get(idx);

				if (slotHash == hash) {
					// Token already exists: update expiration timestamp in place
					table.set(idx + 1, expiresAt);
					return;
				}

				long slotExpiry = table.get(idx + 1);
				if (slotHash == EMPTY_HASH || slotExpiry <= 0L || nowMillis > slotExpiry) {
					if (freeIdx < 0) {
						freeIdx = idx;
						freeExpectedHash = slotHash;
					}
				} else if (slotExpiry < earliestExpiry) {
					earliestExpiry = slotExpiry;
					earliestIdx = idx;
					earliestHash = slotHash;
				}

				if (++slot == capacity) {
					slot = 0;
				}
			}

			int targetIdx = freeIdx >= 0 ? freeIdx : earliestIdx;
			long expectedHash = freeIdx >= 0 ? freeExpectedHash : earliestHash;
			if (targetIdx < 0) {
				targetIdx = baseSlot << 1;
				expectedHash = table.get(targetIdx);
			}

			// Invalidate expiry first so readers never observe (newHash, oldExpiry)
			table.set(targetIdx + 1, 0L);
			if (table.compareAndSet(targetIdx, expectedHash, hash)) {
				table.set(targetIdx + 1, expiresAt);
				return;
			}
		}
	}

	/**
	 * Immediately removes a token from the session cache (e.g. on logout).
	 *
	 * @param tokenValue The raw cookie value to invalidate
	 */
	public void invalidateSession(String tokenValue) {
		long hash = computeHash(tokenValue);
		if (hash == EMPTY_HASH) {
			return;
		}

		TableState current = this.state;
		AtomicLongArray table = current.table;
		int capacity = current.capacity;
		int probeLimit = current.probeLimit;
		int slot = startSlot(hash, capacity);

		for (int step = 0; step < probeLimit; step++) {
			int idx = slot << 1;
			long slotHash = table.get(idx);
			if (slotHash == hash) {
				table.set(idx + 1, 0L);
				table.compareAndSet(idx, hash, EMPTY_HASH);
			}
			if (++slot == capacity) {
				slot = 0;
			}
		}
	}

	/**
	 * Inspects {@code Set-Cookie} response headers from a login endpoint (e.g. {@code /trust})
	 * and registers or invalidates the configured authentication cookie accordingly.
	 *
	 * @param setCookieHeaders   The {@code Set-Cookie} headers present on the HTTP response
	 * @param targetCookieName   The configured login cookie name (e.g. {@code AUTH_COOKIE})
	 * @param defaultTtlSeconds  Fallback TTL in seconds if the {@code Set-Cookie} header omits {@code Max-Age}
	 * @param requestCookieValue Optional previous cookie value sent with the request (invalidated on logout)
	 * @param nowMillis          Current timestamp in milliseconds
	 * @return {@code true} if a valid login cookie was registered, {@code false} otherwise
	 */
	public boolean processSetCookieHeaders(Iterable<String> setCookieHeaders, String targetCookieName,
			int defaultTtlSeconds, String requestCookieValue, long nowMillis) {
		if (setCookieHeaders == null || targetCookieName == null || targetCookieName.isEmpty()) {
			return false;
		}

		boolean foundMatchingHeader = false;
		String effectiveValue = null;
		String deletedValue = null;
		long effectiveTtlMillis = -1L;

		for (String header : setCookieHeaders) {
			ParsedCookie parsed = parseSetCookieHeader(header, targetCookieName, defaultTtlSeconds);
			if (parsed != null) {
				foundMatchingHeader = true;
				if (parsed.deleted()) {
					if (parsed.value() != null && !parsed.value().isEmpty()) {
						deletedValue = parsed.value();
					} else if (effectiveValue != null) {
						deletedValue = effectiveValue;
					}
					effectiveValue = null;
					effectiveTtlMillis = -1L;
				} else {
					effectiveValue = parsed.value();
					effectiveTtlMillis = parsed.ttlMillis();
				}
			}
		}

		if (!foundMatchingHeader) {
			return false;
		}

		if (effectiveValue != null && effectiveTtlMillis > 0) {
			registerSession(effectiveValue, effectiveTtlMillis, nowMillis);
			return true;
		} else {
			if (deletedValue != null && !deletedValue.isEmpty()) {
				invalidateSession(deletedValue);
			}
			if (requestCookieValue != null && !requestCookieValue.isEmpty()) {
				invalidateSession(requestCookieValue);
			}
			return false;
		}
	}

	/**
	 * Represents the parsed outcome of a single {@code Set-Cookie} header matching the target cookie name.
	 */
	record ParsedCookie(String value, long ttlMillis, boolean deleted) {}

	/**
	 * Parses a single {@code Set-Cookie} header string if it matches {@code targetCookieName}.
	 * Returns {@code null} if the header is for a different cookie.
	 */
	static ParsedCookie parseSetCookieHeader(String header, String targetCookieName, int defaultTtlSeconds) {
		if (header == null || header.isEmpty() || targetCookieName == null || targetCookieName.isEmpty()) {
			return null;
		}

		int firstSemi = header.indexOf(';');
		String nameValuePair = firstSemi >= 0 ? header.substring(0, firstSemi) : header;
		int eqIdx = nameValuePair.indexOf('=');
		if (eqIdx <= 0) {
			return null;
		}

		String name = nameValuePair.substring(0, eqIdx).trim();
		if (!targetCookieName.equals(name)) {
			return null;
		}

		String rawValue = nameValuePair.substring(eqIdx + 1).trim();
		if (rawValue.length() >= 2 && rawValue.startsWith("\"") && rawValue.endsWith("\"")) {
			rawValue = rawValue.substring(1, rawValue.length() - 1).trim();
		}

		Long maxAgeSeconds = null;
		if (firstSemi >= 0 && firstSemi + 1 < header.length()) {
			int start = firstSemi + 1;
			int len = header.length();
			while (start < len) {
				int nextSemi = header.indexOf(';', start);
				String attr = (nextSemi >= 0 ? header.substring(start, nextSemi) : header.substring(start)).trim();
				start = nextSemi >= 0 ? nextSemi + 1 : len;

				int attrEq = attr.indexOf('=');
				if (attrEq > 0) {
					String attrName = attr.substring(0, attrEq).trim();
					if ("Max-Age".equalsIgnoreCase(attrName)) {
						String attrVal = attr.substring(attrEq + 1).trim();
						if (attrVal.length() >= 2 && attrVal.startsWith("\"") && attrVal.endsWith("\"")) {
							attrVal = attrVal.substring(1, attrVal.length() - 1).trim();
						}
						try {
							maxAgeSeconds = Long.parseLong(attrVal);
						} catch (NumberFormatException ignored) {
						}
					}
				}
			}
		}

		if (rawValue.isEmpty() || (maxAgeSeconds != null && maxAgeSeconds.longValue() <= 0L)) {
			return new ParsedCookie(rawValue, 0L, true);
		}

		long ttlSeconds = maxAgeSeconds != null ? maxAgeSeconds.longValue() : Math.max(1, defaultTtlSeconds);
		return new ParsedCookie(rawValue, ttlSeconds * 1000L, false);
	}

	/**
	 * Purges any expired entries and returns the current number of active authenticated sessions.
	 * Intended for status dashboard and telemetry queries.
	 *
	 * @param nowMillis Current timestamp in milliseconds
	 * @return Number of active non-expired sessions in the cache
	 */
	public int getActiveSessionCount(long nowMillis) {
		TableState current = this.state;
		AtomicLongArray table = current.table;
		int capacity = current.capacity;
		int active = 0;

		for (int s = 0; s < capacity; s++) {
			int idx = s << 1;
			long h = table.get(idx);
			if (h != EMPTY_HASH) {
				long exp = table.get(idx + 1);
				if (exp > 0L && nowMillis <= exp) {
					active++;
				} else if (exp > 0L && nowMillis > exp) {
					if (table.compareAndSet(idx + 1, exp, 0L)) {
						table.compareAndSet(idx, h, EMPTY_HASH);
					}
				}
			}
		}
		return active;
	}

	/**
	 * Returns the number of occupied slots in the table without checking expiration timestamps.
	 */
	public int getRawSize() {
		TableState current = this.state;
		AtomicLongArray table = current.table;
		int capacity = current.capacity;
		int count = 0;
		for (int s = 0; s < capacity; s++) {
			if (table.get(s << 1) != EMPTY_HASH && table.get((s << 1) + 1) > 0L) {
				count++;
			}
		}
		return count;
	}

	public int getMaxCapacity() {
		return state.capacity;
	}

	public synchronized void setMaxCapacity(int maxCapacity) {
		if (maxCapacity >= 1 && maxCapacity != this.state.capacity) {
			TableState oldState = this.state;
			TableState newState = new TableState(maxCapacity);
			long now = System.currentTimeMillis();

			// Migrate active non-expired entries into the resized table
			AtomicLongArray oldTable = oldState.table;
			for (int s = 0; s < oldState.capacity; s++) {
				int idx = s << 1;
				long h = oldTable.get(idx);
				long exp = oldTable.get(idx + 1);
				if (h != EMPTY_HASH && exp > now) {
					insertHashIntoState(newState, h, exp, now);
				}
			}
			this.state = newState;
		}
	}

	private static void insertHashIntoState(TableState target, long hash, long expiresAt, long nowMillis) {
		AtomicLongArray table = target.table;
		int capacity = target.capacity;
		int probeLimit = target.probeLimit;
		int slot = startSlot(hash, capacity);

		int earliestIdx = -1;
		long earliestExpiry = Long.MAX_VALUE;

		for (int step = 0; step < probeLimit; step++) {
			int idx = slot << 1;
			long slotHash = table.get(idx);
			long slotExpiry = table.get(idx + 1);
			if (slotHash == EMPTY_HASH || slotExpiry <= nowMillis) {
				table.set(idx, hash);
				table.set(idx + 1, expiresAt);
				return;
			}
			if (slotExpiry < earliestExpiry) {
				earliestExpiry = slotExpiry;
				earliestIdx = idx;
			}
			if (++slot == capacity) {
				slot = 0;
			}
		}
		if (earliestIdx >= 0) {
			table.set(earliestIdx, hash);
			table.set(earliestIdx + 1, expiresAt);
		}
	}

	public void clear() {
		TableState current = this.state;
		AtomicLongArray table = current.table;
		int len = table.length();
		for (int i = 0; i < len; i++) {
			table.set(i, 0L);
		}
	}
}
