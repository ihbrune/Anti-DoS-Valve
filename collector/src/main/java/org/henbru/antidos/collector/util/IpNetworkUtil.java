package org.henbru.antidos.collector.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import org.henbru.antidos.collector.model.IpNetworkInfo;

/**
 * Utility for parsing IPv4/IPv6 client keys and search queries into normalized network ranges
 * for efficient database indexing and CIDR containment queries.
 */
public final class IpNetworkUtil {

	private IpNetworkUtil() {
	}

	/**
	 * Parses a clientKey string (e.g. "192.168.1.42", "192.168.1.0/24", "2001:db8::1", "2001:db8::/64")
	 * into structured network information.
	 */
	public static IpNetworkInfo parse(String clientKey) {
		if (clientKey == null || clientKey.trim().isEmpty()) {
			return new IpNetworkInfo(4, 32, null, null, null, null, "");
		}

		String trimmed = clientKey.trim();

		// Check for IPv4
		if (isPossibleIPv4(trimmed)) {
			try {
				return parseIPv4(trimmed);
			} catch (Exception ignored) {
				// Fall through
			}
		}

		// Check for IPv6
		if (trimmed.indexOf(':') >= 0) {
			try {
				return parseIPv6(trimmed);
			} catch (Exception ignored) {
				// Fall through
			}
		}

		// Generic fallback (non-IP counter)
		return new IpNetworkInfo(4, 32, null, null, null, null, trimmed);
	}

	private static boolean isPossibleIPv4(String s) {
		int dotCount = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '.') {
				dotCount++;
			} else if (c != '/' && (c < '0' || c > '9')) {
				return false;
			}
		}
		return dotCount == 3;
	}

	private static IpNetworkInfo parseIPv4(String s) {
		int slashIdx = s.indexOf('/');
		String ipPart = slashIdx >= 0 ? s.substring(0, slashIdx) : s;
		int prefix = slashIdx >= 0 ? Integer.parseInt(s.substring(slashIdx + 1).trim()) : 32;

		if (prefix < 0) {
			prefix = 0;
		} else if (prefix > 32) {
			prefix = 32;
		}

		long ipNum = ipv4ToLong(ipPart);
		long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
		long v4Start = ipNum & mask;
		long v4End = v4Start | (~mask & 0xFFFFFFFFL);

		// Canonical /24 subnet group for prefix >= 24, else original prefix
		String subnetGroup;
		if (prefix >= 24) {
			long cStart = ipNum & 0xFFFFFF00L;
			subnetGroup = longToIPv4(cStart) + "/24";
		} else {
			subnetGroup = longToIPv4(v4Start) + "/" + prefix;
		}

		return new IpNetworkInfo(4, prefix, v4Start, v4End, null, null, subnetGroup);
	}

	private static IpNetworkInfo parseIPv6(String s) {
		int slashIdx = s.indexOf('/');
		String ipPart = slashIdx >= 0 ? s.substring(0, slashIdx) : s;
		int prefix = slashIdx >= 0 ? Integer.parseInt(s.substring(slashIdx + 1).trim()) : 128;

		if (prefix < 0) {
			prefix = 0;
		} else if (prefix > 128) {
			prefix = 128;
		}

		try {
			if (ipPart.startsWith("[") && ipPart.endsWith("]")) {
				ipPart = ipPart.substring(1, ipPart.length() - 1);
			}
			InetAddress addr = InetAddress.getByName(ipPart);
			if (!(addr instanceof Inet6Address)) {
				return new IpNetworkInfo(4, 32, null, null, null, null, s);
			}

			byte[] bytes = addr.getAddress(); // 16 bytes

			// Format upper 64 bits (first 8 bytes)
			int prefixInUpper64 = Math.min(prefix, 64);
			byte[] startBytes = new byte[8];
			byte[] endBytes = new byte[8];
			System.arraycopy(bytes, 0, startBytes, 0, 8);
			System.arraycopy(bytes, 0, endBytes, 0, 8);

			maskUpperBytes(startBytes, endBytes, prefixInUpper64);

			String v6Start = bytesToHex16(startBytes);
			String v6End = bytesToHex16(endBytes);

			// Subnet group: canonical /64
			String subnetGroup;
			if (prefix >= 64) {
				subnetGroup = formatCanonicalIPv6Subnet64(bytes);
			} else {
				subnetGroup = s;
			}

			return new IpNetworkInfo(6, prefix, null, null, v6Start, v6End, subnetGroup);
		} catch (java.net.UnknownHostException | IllegalArgumentException e) {
			return new IpNetworkInfo(6, 128, null, null, null, null, s);
		}
	}

	private static void maskUpperBytes(byte[] start, byte[] end, int prefixBits) {
		int fullBytes = prefixBits / 8;
		int remBits = prefixBits % 8;

		for (int i = fullBytes + (remBits > 0 ? 1 : 0); i < 8; i++) {
			start[i] = 0;
			end[i] = (byte) 0xFF;
		}

		if (remBits > 0 && fullBytes < 8) {
			int mask = (0xFF << (8 - remBits)) & 0xFF;
			start[fullBytes] = (byte) (start[fullBytes] & mask);
			end[fullBytes] = (byte) (start[fullBytes] | (~mask & 0xFF));
		}
	}

	private static String bytesToHex16(byte[] b) {
		StringBuilder sb = new StringBuilder(16);
		for (int i = 0; i < 8; i++) {
			sb.append(String.format("%02x", b[i] & 0xFF));
		}
		return sb.toString();
	}

	private static String formatCanonicalIPv6Subnet64(byte[] b) {
		int g1 = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
		int g2 = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
		int g3 = ((b[4] & 0xFF) << 8) | (b[5] & 0xFF);
		int g4 = ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
		return String.format("%x:%x:%x:%x::/64", g1, g2, g3, g4);
	}

	public static long ipv4ToLong(String ip) {
		String[] parts = ip.split("\\.");
		long result = 0;
		for (int i = 0; i < 4; i++) {
			long octet = Long.parseLong(parts[i].trim());
			result = (result << 8) | (octet & 0xFF);
		}
		return result & 0xFFFFFFFFL;
	}

	public static String longToIPv4(long num) {
		return ((num >> 24) & 0xFF) + "." +
				((num >> 16) & 0xFF) + "." +
				((num >> 8) & 0xFF) + "." +
				(num & 0xFF);
	}

	/**
	 * Represents the parsed search criteria for client/subnet queries.
	 */
	public record SearchCriteria(
			boolean hasFilter,
			boolean isIpSearch,
			Integer ipVersion,
			Long v4Start,
			Long v4End,
			String v6Start,
			String v6End,
			String rawQuery
	) {
	}

	/**
	 * Parses user query input from search fields into network bounds or wildcard text.
	 */
	public static SearchCriteria parseSearchQuery(String query) {
		if (query == null || query.trim().isEmpty()) {
			return new SearchCriteria(false, false, null, null, null, null, null, "");
		}

		String q = query.trim();

		// Handle IPv4 shorthand prefix, e.g. "192.168.1." or "192.168.1" -> /24, "192.168." or "192.168" -> /16, "10." -> /8
		if (q.endsWith(".")) {
			String[] dots = q.split("\\.");
			switch (dots.length) {
				case 3 -> q = q + "0/24";
				case 2 -> q = q + "0.0/16";
				case 1 -> q = q + "0.0.0/8";
				default -> {
				}
			}
		} else if (isOctetsWithoutTrailingDot(q)) {
			String[] dots = q.split("\\.");
			switch (dots.length) {
				case 3 -> q = q + ".0/24";
				case 2 -> q = q + ".0.0/16";
				default -> {
				}
			}
		}

		// Try parsing as IPv4
		if (isPossibleIPv4(q)) {
			try {
				IpNetworkInfo info = parseIPv4(q);
				return new SearchCriteria(true, true, 4, info.v4Start(), info.v4End(), null, null, query.trim());
			} catch (Exception ignored) {
			}
		}

		// Try parsing as IPv6
		if (q.indexOf(':') >= 0) {
			try {
				IpNetworkInfo info = parseIPv6(q);
				return new SearchCriteria(true, true, 6, null, null, info.v6Start(), info.v6End(), query.trim());
			} catch (Exception ignored) {
			}
		}

		// Fallback: simple text match
		return new SearchCriteria(true, false, null, null, null, null, null, query.trim());
	}

	private static boolean isOctetsWithoutTrailingDot(String s) {
		String[] parts = s.split("\\.");
		if (parts.length != 2 && parts.length != 3) {
			return false;
		}
		for (String part : parts) {
			if (part.isEmpty() || part.length() > 3) {
				return false;
			}
			for (int i = 0; i < part.length(); i++) {
				char c = part.charAt(i);
				if (c < '0' || c > '9') {
					return false;
				}
			}
			try {
				int val = Integer.parseInt(part);
				if (val < 0 || val > 255) {
					return false;
				}
			} catch (NumberFormatException e) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Checks whether the given clientKey, IP address, or CIDR network belongs to a private,
	 * loopback, link-local, or unique-local (ULA) address range.
	 */
	public static boolean isPrivateOrLocal(String clientKey) {
		return getPrivateNetworkDescription(clientKey) != null;
	}

	/**
	 * Returns a human-readable description for private/local IP ranges (e.g. "Private Network (RFC 1918)",
	 * "Loopback / Localhost", "Unique Local Address (RFC 4193)", "Link-Local"), or null if public/routable.
	 */
	public static String getPrivateNetworkDescription(String clientKey) {
		if (clientKey == null || clientKey.trim().isEmpty()) {
			return null;
		}
		String s = clientKey.trim();
		int slashIdx = s.indexOf('/');
		if (slashIdx >= 0) {
			s = s.substring(0, slashIdx);
		}
		if (s.startsWith("[") && s.endsWith("]")) {
			s = s.substring(1, s.length() - 1);
		}

		if (isPossibleIPv4(s)) {
			try {
				long ipNum = ipv4ToLong(s);
				long firstOctet = (ipNum >>> 24) & 0xFF;
				long secondOctet = (ipNum >>> 16) & 0xFF;

				// 10.0.0.0/8 (RFC 1918)
				if (firstOctet == 10) {
					return "Private Network (RFC 1918)";
				}
				// 172.16.0.0/12 (RFC 1918: 172.16.0.0 - 172.31.255.255)
				if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) {
					return "Private Network (RFC 1918)";
				}
				// 192.168.0.0/16 (RFC 1918)
				if (firstOctet == 192 && secondOctet == 168) {
					return "Private Network (RFC 1918)";
				}
				// 127.0.0.0/8 (Loopback RFC 1122)
				if (firstOctet == 127) {
					return "Loopback / Localhost";
				}
				// 169.254.0.0/16 (Link-Local RFC 3927)
				if (firstOctet == 169 && secondOctet == 254) {
					return "Link-Local";
				}
				// 100.64.0.0/10 (CGNAT / Shared Address Space RFC 6598: 100.64.0.0 - 100.127.255.255)
				if (firstOctet == 100 && (secondOctet & 0xC0) == 64) {
					return "Shared Address Space (RFC 6598)";
				}
				// 0.0.0.0/8 (Current / Unspecified)
				if (firstOctet == 0) {
					return "Local Network";
				}
				return null;
			} catch (NumberFormatException | IndexOutOfBoundsException ignored) {
				return null;
			}
		}

		if (s.indexOf(':') >= 0) {
			try {
				InetAddress addr = InetAddress.getByName(s);
				if (!(addr instanceof Inet6Address)) {
					return null;
				}
				if (addr.isLoopbackAddress()) {
					return "Loopback / Localhost";
				}
				if (addr.isAnyLocalAddress()) {
					return "Local Network";
				}
				if (addr.isLinkLocalAddress()) {
					return "Link-Local";
				}
				byte[] bytes = addr.getAddress();
				if (bytes != null && bytes.length == 16) {
					int b0 = bytes[0] & 0xFF;
					// fc00::/7 (RFC 4193 Unique Local Address - ULA, covers fc00::/8 and fd00::/8)
					if (b0 >= 0xFC && b0 <= 0xFD) {
						return "Unique Local Address (RFC 4193)";
					}
					// Deprecated IPv6 site-local fec0::/10
					int b1 = bytes[1] & 0xFF;
					if (b0 == 0xFE && (b1 & 0xC0) == 0xC0) {
						return "Private Network (Site-Local)";
					}
				}
				return null;
			} catch (java.net.UnknownHostException | IllegalArgumentException | SecurityException ignored) {
				return null;
			}
		}

		return null;
	}
}
