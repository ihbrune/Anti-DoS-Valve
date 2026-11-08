package org.henbru.antidos;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Lock-free, high-concurrency registry for dynamic CIDR block rules with automatic TTL expiration.
 * <p>
 * Designed for Tomcat's hot request processing path ({@code invoke()}):
 * <ul>
 *   <li>When no dynamic blocks are active, {@link #match(String, byte[], long)} performs a single
 *       volatile array length check (~1 ns) and returns {@code null}.</li>
 *   <li>When hundreds or thousands of subnets are blocked, lookups only probe the distinct prefix
 *       lengths actually present (e.g. {@code /24} and {@code /32}) via primitive bitmasking and
 *       {@link ConcurrentHashMap} lookups in {@code O(1)} per active prefix length.</li>
 *   <li>Expired entries become inactive at the exact millisecond their TTL elapses without
 *       requiring external coordination from the Collector.</li>
 * </ul>
 */
public class AntiDoSDynamicBlockRegistry {

	private static final int[] EMPTY_MASKS = new int[0];

	@SuppressWarnings("unchecked")
	private final ConcurrentHashMap<Integer, DynamicBlockEntry>[] ipv4Tables = new ConcurrentHashMap[33];

	@SuppressWarnings("unchecked")
	private final ConcurrentHashMap<Ipv6PrefixKey, DynamicBlockEntry>[] ipv6Tables = new ConcurrentHashMap[129];

	private volatile int[] activeIpv4Masks = EMPTY_MASKS;
	private volatile int[] activeIpv6Masks = EMPTY_MASKS;

	private final ConcurrentHashMap<String, DynamicBlockEntry> entriesByCidr = new ConcurrentHashMap<>();
	private final LongAdder totalBlockedRequests = new LongAdder();

	public AntiDoSDynamicBlockRegistry() {
		for (int i = 1; i <= 32; i++) {
			ipv4Tables[i] = new ConcurrentHashMap<>();
		}
		for (int i = 1; i <= 128; i++) {
			ipv6Tables[i] = new ConcurrentHashMap<>();
		}
	}

	/**
	 * Checks whether the given client IP matches any currently active (non-expired) dynamic CIDR block.
	 *
	 * @param ip             Client IP address string
	 * @param preParsedIpv4  Optional 4-byte IPv4 array if already parsed by caller (may be null)
	 * @param nowMillis      Current epoch time in milliseconds
	 * @return Matching {@link DynamicBlockEntry} if blocked, or {@code null} if allowed
	 */
	public DynamicBlockEntry match(String ip, byte[] preParsedIpv4, long nowMillis) {
		int[] v4Masks = this.activeIpv4Masks;
		int[] v6Masks = this.activeIpv6Masks;
		if (v4Masks.length == 0 && v6Masks.length == 0) {
			return null;
		}
		if (ip == null || ip.isEmpty()) {
			return null;
		}

		if (ip.indexOf(':') < 0) {
			if (v4Masks.length == 0) {
				return null;
			}
			byte[] ipv4 = preParsedIpv4 != null ? preParsedIpv4 : parseIPv4Literal(ip);
			if (ipv4 == null) {
				return null;
			}
			int addr = ((ipv4[0] & 0xFF) << 24)
					| ((ipv4[1] & 0xFF) << 16)
					| ((ipv4[2] & 0xFF) << 8)
					| (ipv4[3] & 0xFF);

			for (int i = 0; i < v4Masks.length; i++) {
				int prefixBits = v4Masks[i];
				int masked = maskIpv4Int(addr, prefixBits);
				DynamicBlockEntry entry = ipv4Tables[prefixBits].get(Integer.valueOf(masked));
				if (entry != null) {
					if (nowMillis < entry.getExpiresAtMillis()) {
						return entry;
					}
					// Lazily evict expired entry
					removeExpiredEntry(entry, nowMillis);
				}
			}
			return null;
		} else {
			if (v6Masks.length == 0) {
				return null;
			}
			byte[] ipv6 = parseIPv6Bytes(ip);
			if (ipv6 == null) {
				return null;
			}
			long hi = bytesToLong(ipv6, 0);
			long lo = bytesToLong(ipv6, 8);

			for (int i = 0; i < v6Masks.length; i++) {
				int prefixBits = v6Masks[i];
				Ipv6PrefixKey key = maskIpv6Key(hi, lo, prefixBits);
				DynamicBlockEntry entry = ipv6Tables[prefixBits].get(key);
				if (entry != null) {
					if (nowMillis < entry.getExpiresAtMillis()) {
						return entry;
					}
					removeExpiredEntry(entry, nowMillis);
				}
			}
			return null;
		}
	}

	/**
	 * Records a blocked request against the given entry and the cumulative registry counter.
	 */
	public void recordBlockedHit(DynamicBlockEntry entry, long nowMillis) {
		totalBlockedRequests.increment();
		if (entry != null) {
			entry.recordHit(nowMillis);
		}
	}

	/**
	 * Inserts or updates a dynamic CIDR block rule.
	 * If the CIDR is already present, its hit counters and creation timestamp are preserved
	 * while its expiration timestamp and reason are updated.
	 *
	 * @param rawCidr         IP or CIDR string (e.g. "198.51.100.0/24" or "203.0.113.12")
	 * @param expiresAtMillis Expiration epoch timestamp in milliseconds
	 * @param reason          Optional audit reason
	 * @param nowMillis       Current epoch timestamp in milliseconds
	 * @return The canonical {@link DynamicBlockEntry}, or {@code null} if already expired
	 * @throws IllegalArgumentException If the CIDR syntax is invalid
	 */
	public synchronized DynamicBlockEntry upsertBlock(String rawCidr, long expiresAtMillis, String reason, long nowMillis) {
		ParsedCidr parsed = parseAndNormalizeCidr(rawCidr);
		if (expiresAtMillis <= nowMillis) {
			removeBlock(parsed.canonicalCidr);
			return null;
		}

		String safeReason = (reason != null && !reason.trim().isEmpty()) ? reason.trim() : "Dynamic Mitigation";
		if (safeReason.length() > 160) {
			safeReason = safeReason.substring(0, 160);
		}

		DynamicBlockEntry existing = entriesByCidr.get(parsed.canonicalCidr);
		DynamicBlockEntry entry;
		if (existing != null) {
			existing.setExpiresAtMillis(expiresAtMillis);
			existing.setReason(safeReason);
			entry = existing;
		} else {
			entry = new DynamicBlockEntry(
					parsed.canonicalCidr,
					parsed.prefixBits,
					parsed.ipv6,
					parsed.ipv4MaskedInt,
					parsed.ipv6Key,
					nowMillis,
					expiresAtMillis,
					safeReason
			);
			entriesByCidr.put(parsed.canonicalCidr, entry);
		}

		if (parsed.ipv6) {
			ipv6Tables[parsed.prefixBits].put(parsed.ipv6Key, entry);
		} else {
			ipv4Tables[parsed.prefixBits].put(Integer.valueOf(parsed.ipv4MaskedInt), entry);
		}

		rebuildActiveMasks();
		return entry;
	}

	/**
	 * Removes a dynamic CIDR block rule immediately.
	 *
	 * @param rawCidr IP or CIDR string
	 * @return {@code true} if an entry was removed
	 */
	public synchronized boolean removeBlock(String rawCidr) {
		if (rawCidr == null || rawCidr.trim().isEmpty()) {
			return false;
		}
		String canonical;
		try {
			canonical = parseAndNormalizeCidr(rawCidr).canonicalCidr;
		} catch (IllegalArgumentException e) {
			canonical = rawCidr.trim();
		}

		DynamicBlockEntry removed = entriesByCidr.remove(canonical);
		if (removed == null) {
			return false;
		}
		if (removed.isIpv6()) {
			ipv6Tables[removed.getPrefixBits()].remove(removed.getIpv6Key());
		} else {
			ipv4Tables[removed.getPrefixBits()].remove(Integer.valueOf(removed.getIpv4MaskedInt()));
		}
		rebuildActiveMasks();
		return true;
	}

	/**
	 * Atomically reconciles the registry with the given full set of block specifications,
	 * preserving hit counters for rules that remain active and removing rules not present in {@code specs}.
	 */
	public synchronized int replaceAllBlocks(Collection<BlockSpec> specs, long nowMillis) {
		return replaceAllBlocks(specs, nowMillis, 0);
	}

	/**
	 * Atomically reconciles the registry with the given full set of block specifications,
	 * enforcing an upper limit for the number of active rules. If the resulting rule set would
	 * exceed {@code maxActiveBlocks}, the registry is left untouched.
	 *
	 * @param specs           Full desired set of block specifications
	 * @param nowMillis       Current epoch timestamp in milliseconds
	 * @param maxActiveBlocks Maximum number of active rules, or {@code <= 0} for unlimited
	 * @return Number of entries after reconciliation
	 * @throws CapacityExceededException If the desired set exceeds {@code maxActiveBlocks}
	 * @throws IllegalArgumentException  If a CIDR is syntactically invalid
	 */
	public synchronized int replaceAllBlocks(Collection<BlockSpec> specs, long nowMillis, int maxActiveBlocks) {
		if (maxActiveBlocks > 0 && specs != null) {
			Set<String> desired = new HashSet<>();
			for (BlockSpec spec : specs) {
				if (spec != null && spec.cidr != null && spec.expiresAtMillis > nowMillis) {
					desired.add(parseAndNormalizeCidr(spec.cidr).canonicalCidr);
				}
			}
			if (desired.size() > maxActiveBlocks) {
				throw new CapacityExceededException("Replace command contains " + desired.size()
						+ " active dynamic blocks, exceeding mitigationMaxActiveBlocks=" + maxActiveBlocks);
			}
		}
		return replaceAllBlocksUnchecked(specs, nowMillis);
	}

	/**
	 * Atomically upserts the given block specifications, enforcing an upper limit for the number
	 * of active rules. If adding the new (not yet active) CIDRs would exceed {@code maxActiveBlocks},
	 * none of the specifications are applied.
	 *
	 * @param specs           Block specifications to insert or update
	 * @param nowMillis       Current epoch timestamp in milliseconds
	 * @param maxActiveBlocks Maximum number of active rules, or {@code <= 0} for unlimited
	 * @return Number of active entries after the upsert
	 * @throws CapacityExceededException If the resulting rule set would exceed {@code maxActiveBlocks}
	 * @throws IllegalArgumentException  If a CIDR is syntactically invalid
	 */
	public synchronized int upsertBlocks(Collection<BlockSpec> specs, long nowMillis, int maxActiveBlocks) {
		if (specs == null || specs.isEmpty()) {
			return getActiveCount(nowMillis);
		}
		if (maxActiveBlocks > 0) {
			int active = 0;
			for (DynamicBlockEntry entry : entriesByCidr.values()) {
				if (nowMillis < entry.getExpiresAtMillis()) {
					active++;
				}
			}
			Set<String> newCidrs = new HashSet<>();
			for (BlockSpec spec : specs) {
				if (spec == null || spec.cidr == null || spec.expiresAtMillis <= nowMillis) {
					continue;
				}
				String canonical = parseAndNormalizeCidr(spec.cidr).canonicalCidr;
				DynamicBlockEntry existing = entriesByCidr.get(canonical);
				if (existing == null || nowMillis >= existing.getExpiresAtMillis()) {
					newCidrs.add(canonical);
				}
			}
			if (active + newCidrs.size() > maxActiveBlocks) {
				throw new CapacityExceededException("Upsert would raise active dynamic blocks to " + (active + newCidrs.size())
						+ ", exceeding mitigationMaxActiveBlocks=" + maxActiveBlocks + " (currently active: " + active + ")");
			}
		}
		for (BlockSpec spec : specs) {
			if (spec == null || spec.cidr == null) {
				continue;
			}
			upsertBlock(spec.cidr, spec.expiresAtMillis, spec.reason, nowMillis);
		}
		return getActiveCount(nowMillis);
	}

	private int replaceAllBlocksUnchecked(Collection<BlockSpec> specs, long nowMillis) {
		Set<String> keepCanonical = new HashSet<>();
		if (specs != null) {
			for (BlockSpec spec : specs) {
				if (spec == null || spec.cidr == null || spec.expiresAtMillis <= nowMillis) {
					continue;
				}
				ParsedCidr parsed = parseAndNormalizeCidr(spec.cidr);
				keepCanonical.add(parsed.canonicalCidr);
				upsertBlock(parsed.canonicalCidr, spec.expiresAtMillis, spec.reason, nowMillis);
			}
		}

		List<String> toRemove = new ArrayList<>();
		for (String existingCidr : entriesByCidr.keySet()) {
			if (!keepCanonical.contains(existingCidr)) {
				toRemove.add(existingCidr);
			}
		}
		for (String cidr : toRemove) {
			DynamicBlockEntry removed = entriesByCidr.remove(cidr);
			if (removed != null) {
				if (removed.isIpv6()) {
					ipv6Tables[removed.getPrefixBits()].remove(removed.getIpv6Key());
				} else {
					ipv4Tables[removed.getPrefixBits()].remove(Integer.valueOf(removed.getIpv4MaskedInt()));
				}
			}
		}
		rebuildActiveMasks();
		return entriesByCidr.size();
	}

	/**
	 * Clears all dynamic blocks immediately.
	 */
	public synchronized void clearAll() {
		entriesByCidr.clear();
		for (int i = 1; i <= 32; i++) {
			ipv4Tables[i].clear();
		}
		for (int i = 1; i <= 128; i++) {
			ipv6Tables[i].clear();
		}
		activeIpv4Masks = EMPTY_MASKS;
		activeIpv6Masks = EMPTY_MASKS;
	}

	/**
	 * Purges all expired dynamic block entries from memory.
	 *
	 * @param nowMillis Current epoch timestamp in milliseconds
	 * @return Number of expired entries evicted
	 */
	public int evictExpired(long nowMillis) {
		if (entriesByCidr.isEmpty()) {
			return 0;
		}
		int evicted = 0;
		for (Map.Entry<String, DynamicBlockEntry> e : entriesByCidr.entrySet()) {
			DynamicBlockEntry entry = e.getValue();
			if (nowMillis >= entry.getExpiresAtMillis()) {
				removeExpiredEntry(entry, nowMillis);
				evicted++;
			}
		}
		return evicted;
	}

	private synchronized void removeExpiredEntry(DynamicBlockEntry entry, long nowMillis) {
		if (nowMillis < entry.getExpiresAtMillis()) {
			return;
		}
		if (entriesByCidr.remove(entry.getCidr(), entry)) {
			if (entry.isIpv6()) {
				ipv6Tables[entry.getPrefixBits()].remove(entry.getIpv6Key(), entry);
			} else {
				ipv4Tables[entry.getPrefixBits()].remove(Integer.valueOf(entry.getIpv4MaskedInt()), entry);
			}
			rebuildActiveMasks();
		}
	}

	private void rebuildActiveMasks() {
		int v4Count = 0;
		for (int i = 32; i >= 1; i--) {
			if (!ipv4Tables[i].isEmpty()) {
				v4Count++;
			}
		}
		if (v4Count == 0) {
			activeIpv4Masks = EMPTY_MASKS;
		} else {
			int[] masks = new int[v4Count];
			int idx = 0;
			// Order from most specific (/32, /24) to least specific (/16, /8)
			for (int i = 32; i >= 1; i--) {
				if (!ipv4Tables[i].isEmpty()) {
					masks[idx++] = i;
				}
			}
			activeIpv4Masks = masks;
		}

		int v6Count = 0;
		for (int i = 128; i >= 1; i--) {
			if (!ipv6Tables[i].isEmpty()) {
				v6Count++;
			}
		}
		if (v6Count == 0) {
			activeIpv6Masks = EMPTY_MASKS;
		} else {
			int[] masks = new int[v6Count];
			int idx = 0;
			for (int i = 128; i >= 1; i--) {
				if (!ipv6Tables[i].isEmpty()) {
					masks[idx++] = i;
				}
			}
			activeIpv6Masks = masks;
		}
	}

	/**
	 * Returns all currently active (non-expired) entries sorted by CIDR.
	 */
	public List<DynamicBlockEntry> getActiveEntries(long nowMillis) {
		if (entriesByCidr.isEmpty()) {
			return Collections.emptyList();
		}
		List<DynamicBlockEntry> result = new ArrayList<>(entriesByCidr.size());
		for (DynamicBlockEntry entry : entriesByCidr.values()) {
			if (nowMillis < entry.getExpiresAtMillis()) {
				result.add(entry);
			}
		}
		result.sort(Comparator.comparing(DynamicBlockEntry::getCidr));
		return result;
	}

	public int getActiveCount(long nowMillis) {
		if (entriesByCidr.isEmpty()) {
			return 0;
		}
		int count = 0;
		for (DynamicBlockEntry entry : entriesByCidr.values()) {
			if (nowMillis < entry.getExpiresAtMillis()) {
				count++;
			}
		}
		return count;
	}

	/**
	 * Looks up an active (non-expired) dynamic block entry by its exact canonical CIDR key.
	 */
	public DynamicBlockEntry getActiveEntryByCidr(String cidrKey, long nowMillis) {
		if (cidrKey == null || entriesByCidr.isEmpty()) {
			return null;
		}
		DynamicBlockEntry entry = entriesByCidr.get(cidrKey);
		if (entry != null && nowMillis < entry.getExpiresAtMillis()) {
			return entry;
		}
		return null;
	}

	public long getTotalBlockedRequests() {
		return totalBlockedRequests.sum();
	}

	/**
	 * Computes a deterministic 64-bit positive revision hash over all active canonical CIDRs.
	 * Returns {@code 0L} when no dynamic blocks are active.
	 */
	public long getRevision(long nowMillis) {
		if (entriesByCidr.isEmpty()) {
			return 0L;
		}
		List<String> activeCidrs = new ArrayList<>(entriesByCidr.size());
		for (DynamicBlockEntry entry : entriesByCidr.values()) {
			if (nowMillis < entry.getExpiresAtMillis()) {
				activeCidrs.add(entry.getCidr());
			}
		}
		return computeRevisionForCidrs(activeCidrs);
	}

	/**
	 * Deterministic FNV-1a 53-bit positive hash over sorted canonical CIDRs.
	 * Safe for JSON numeric serialization and cross-JVM comparison between Collector and Valve.
	 */
	public static long computeRevisionForCidrs(Collection<String> cidrs) {
		if (cidrs == null || cidrs.isEmpty()) {
			return 0L;
		}
		List<String> sorted = new ArrayList<>(cidrs);
		Collections.sort(sorted);
		long hash = 0xcbf29ce484222325L;
		for (String cidr : sorted) {
			if (cidr == null) {
				continue;
			}
			for (int i = 0; i < cidr.length(); i++) {
				hash ^= cidr.charAt(i);
				hash *= 0x100000001b3L;
			}
			hash ^= '\n';
			hash *= 0x100000001b3L;
		}
		// Mask to 53-bit positive integer for safe JSON compatibility
		long rev = hash & 0x1FFFFFFFFFFFFFL;
		return rev == 0L ? 1L : rev;
	}

	/**
	 * Parses and normalizes an IPv4 or IPv6 address or CIDR string into its canonical network form
	 * (e.g. {@code "198.51.100.55/24"} -> {@code "198.51.100.0/24"}, {@code "203.0.113.4"} -> {@code "203.0.113.4/32"}).
	 */
	public static ParsedCidr parseAndNormalizeCidr(String rawCidr) {
		if (rawCidr == null || rawCidr.trim().isEmpty()) {
			throw new IllegalArgumentException("CIDR must not be null or empty");
		}
		String s = rawCidr.trim();
		int slashIdx = s.indexOf('/');
		String ipPart = slashIdx >= 0 ? s.substring(0, slashIdx).trim() : s;
		String prefixPart = slashIdx >= 0 ? s.substring(slashIdx + 1).trim() : null;

		if (ipPart.indexOf(':') < 0) {
			byte[] ipv4 = parseIPv4Literal(ipPart);
			if (ipv4 == null) {
				throw new IllegalArgumentException("Invalid IPv4 address in CIDR: " + rawCidr);
			}
			int prefix = 32;
			if (prefixPart != null) {
				try {
					prefix = Integer.parseInt(prefixPart);
				} catch (NumberFormatException e) {
					throw new IllegalArgumentException("Invalid IPv4 prefix length in CIDR: " + rawCidr, e);
				}
				if (prefix < 1 || prefix > 32) {
					throw new IllegalArgumentException("IPv4 prefix length must be between 1 and 32: " + rawCidr);
				}
			}
			int addr = ((ipv4[0] & 0xFF) << 24)
					| ((ipv4[1] & 0xFF) << 16)
					| ((ipv4[2] & 0xFF) << 8)
					| (ipv4[3] & 0xFF);
			int masked = maskIpv4Int(addr, prefix);
			String canonical = ((masked >>> 24) & 0xFF) + "."
					+ ((masked >>> 16) & 0xFF) + "."
					+ ((masked >>> 8) & 0xFF) + "."
					+ (masked & 0xFF) + "/" + prefix;
			return new ParsedCidr(canonical, prefix, false, masked, null);
		} else {
			byte[] ipv6 = parseIPv6Bytes(ipPart);
			if (ipv6 == null) {
				throw new IllegalArgumentException("Invalid IPv6 address in CIDR: " + rawCidr);
			}
			int prefix = 128;
			if (prefixPart != null) {
				try {
					prefix = Integer.parseInt(prefixPart);
				} catch (NumberFormatException e) {
					throw new IllegalArgumentException("Invalid IPv6 prefix length in CIDR: " + rawCidr, e);
				}
				if (prefix < 1 || prefix > 128) {
					throw new IllegalArgumentException("IPv6 prefix length must be between 1 and 128: " + rawCidr);
				}
			}
			long hi = bytesToLong(ipv6, 0);
			long lo = bytesToLong(ipv6, 8);
			Ipv6PrefixKey key = maskIpv6Key(hi, lo, prefix);
			byte[] maskedBytes = new byte[16];
			longToBytes(key.hi, maskedBytes, 0);
			longToBytes(key.lo, maskedBytes, 8);
			try {
				String canonicalIp = InetAddress.getByAddress(maskedBytes).getHostAddress();
				return new ParsedCidr(canonicalIp + "/" + prefix, prefix, true, 0, key);
			} catch (UnknownHostException e) {
				throw new IllegalArgumentException("Invalid IPv6 address in CIDR: " + rawCidr, e);
			}
		}
	}

	private static int maskIpv4Int(int addr, int prefixBits) {
		if (prefixBits >= 32) {
			return addr;
		}
		if (prefixBits <= 0) {
			return 0;
		}
		int mask = (int) (0xFFFFFFFF00000000L >>> prefixBits);
		return addr & mask;
	}

	private static Ipv6PrefixKey maskIpv6Key(long hi, long lo, int prefixBits) {
		if (prefixBits >= 128) {
			return new Ipv6PrefixKey(hi, lo);
		}
		if (prefixBits <= 0) {
			return new Ipv6PrefixKey(0L, 0L);
		}
		if (prefixBits == 64) {
			return new Ipv6PrefixKey(hi, 0L);
		}
		if (prefixBits < 64) {
			long maskHi = ~0L << (64 - prefixBits);
			return new Ipv6PrefixKey(hi & maskHi, 0L);
		}
		long maskLo = ~0L << (128 - prefixBits);
		return new Ipv6PrefixKey(hi, lo & maskLo);
	}

	private static byte[] parseIPv4Literal(String ip) {
		int len = ip.length();
		if (len < 7 || len > 15) {
			return null;
		}
		int octetCount = 0;
		byte[] bytes = new byte[4];
		int curOctet = 0;
		int digits = 0;
		for (int i = 0; i < len; i++) {
			char c = ip.charAt(i);
			if (c >= '0' && c <= '9') {
				curOctet = curOctet * 10 + (c - '0');
				digits++;
				if (digits > 3 || curOctet > 255) {
					return null;
				}
			} else if (c == '.') {
				if (digits == 0 || octetCount == 3) {
					return null;
				}
				bytes[octetCount++] = (byte) curOctet;
				curOctet = 0;
				digits = 0;
			} else {
				return null;
			}
		}
		if (digits == 0 || octetCount != 3) {
			return null;
		}
		bytes[3] = (byte) curOctet;
		return bytes;
	}

	private static byte[] parseIPv6Bytes(String ip) {
		try {
			InetAddress addr = InetAddress.getByName(ip);
			if (addr instanceof Inet6Address) {
				return addr.getAddress();
			}
		} catch (UnknownHostException ignored) {
		}
		return null;
	}

	private static long bytesToLong(byte[] b, int offset) {
		return ((long) (b[offset] & 0xFF) << 56)
				| ((long) (b[offset + 1] & 0xFF) << 48)
				| ((long) (b[offset + 2] & 0xFF) << 40)
				| ((long) (b[offset + 3] & 0xFF) << 32)
				| ((long) (b[offset + 4] & 0xFF) << 24)
				| ((long) (b[offset + 5] & 0xFF) << 16)
				| ((long) (b[offset + 6] & 0xFF) << 8)
				| ((long) (b[offset + 7] & 0xFF));
	}

	private static void longToBytes(long val, byte[] b, int offset) {
		b[offset] = (byte) (val >>> 56);
		b[offset + 1] = (byte) (val >>> 48);
		b[offset + 2] = (byte) (val >>> 40);
		b[offset + 3] = (byte) (val >>> 32);
		b[offset + 4] = (byte) (val >>> 24);
		b[offset + 5] = (byte) (val >>> 16);
		b[offset + 6] = (byte) (val >>> 8);
		b[offset + 7] = (byte) val;
	}

	public static final class ParsedCidr {
		public final String canonicalCidr;
		public final int prefixBits;
		public final boolean ipv6;
		final int ipv4MaskedInt;
		final Ipv6PrefixKey ipv6Key;

		ParsedCidr(String canonicalCidr, int prefixBits, boolean ipv6, int ipv4MaskedInt, Ipv6PrefixKey ipv6Key) {
			this.canonicalCidr = canonicalCidr;
			this.prefixBits = prefixBits;
			this.ipv6 = ipv6;
			this.ipv4MaskedInt = ipv4MaskedInt;
			this.ipv6Key = ipv6Key;
		}
	}

	/**
	 * Thrown when a mitigation command would exceed the configured maximum number of active dynamic blocks.
	 * The registry is left unchanged in this case.
	 */
	public static final class CapacityExceededException extends IllegalStateException {
		private static final long serialVersionUID = 1L;

		public CapacityExceededException(String message) {
			super(message);
		}
	}

	public static final class BlockSpec {
		public final String cidr;
		public final long expiresAtMillis;
		public final String reason;

		public BlockSpec(String cidr, long expiresAtMillis, String reason) {
			this.cidr = cidr;
			this.expiresAtMillis = expiresAtMillis;
			this.reason = reason;
		}
	}

	static final class Ipv6PrefixKey {
		final long hi;
		final long lo;

		Ipv6PrefixKey(long hi, long lo) {
			this.hi = hi;
			this.lo = lo;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (!(o instanceof Ipv6PrefixKey that)) return false;
			return hi == that.hi && lo == that.lo;
		}

		@Override
		public int hashCode() {
			return Long.hashCode(hi) * 31 + Long.hashCode(lo);
		}
	}

	/**
	 * Represents a single active dynamic CIDR block rule and its runtime hit telemetry.
	 */
	public static final class DynamicBlockEntry {
		private final String cidr;
		private final int prefixBits;
		private final boolean ipv6;
		private final int ipv4MaskedInt;
		private final Ipv6PrefixKey ipv6Key;
		private final long createdAtMillis;
		private volatile long expiresAtMillis;
		private volatile String reason;
		private final LongAdder blockedRequests = new LongAdder();
		private final AtomicLong lastHitMillis = new AtomicLong(0L);

		DynamicBlockEntry(
				String cidr,
				int prefixBits,
				boolean ipv6,
				int ipv4MaskedInt,
				Ipv6PrefixKey ipv6Key,
				long createdAtMillis,
				long expiresAtMillis,
				String reason) {
			this.cidr = cidr;
			this.prefixBits = prefixBits;
			this.ipv6 = ipv6;
			this.ipv4MaskedInt = ipv4MaskedInt;
			this.ipv6Key = ipv6Key;
			this.createdAtMillis = createdAtMillis;
			this.expiresAtMillis = expiresAtMillis;
			this.reason = reason;
		}

		void recordHit(long nowMillis) {
			blockedRequests.increment();
			lastHitMillis.set(nowMillis);
		}

		public String getCidr() {
			return cidr;
		}

		public int getPrefixBits() {
			return prefixBits;
		}

		public boolean isIpv6() {
			return ipv6;
		}

		int getIpv4MaskedInt() {
			return ipv4MaskedInt;
		}

		Ipv6PrefixKey getIpv6Key() {
			return ipv6Key;
		}

		public long getCreatedAtMillis() {
			return createdAtMillis;
		}

		public long getExpiresAtMillis() {
			return expiresAtMillis;
		}

		void setExpiresAtMillis(long expiresAtMillis) {
			this.expiresAtMillis = expiresAtMillis;
		}

		public String getReason() {
			return reason;
		}

		void setReason(String reason) {
			this.reason = reason;
		}

		public long getBlockedRequests() {
			return blockedRequests.sum();
		}

		public long getLastHitMillis() {
			return lastHitMillis.get();
		}

		public long getRemainingSeconds(long nowMillis) {
			long diff = expiresAtMillis - nowMillis;
			return diff > 0 ? (diff + 999L) / 1000L : 0L;
		}
	}
}
