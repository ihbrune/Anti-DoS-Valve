package org.henbru.antidos;

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
 * High-performance, lock-free 256-bit cardinality tracker used by AntiDoSCounter
 * to track the number of distinct client IP addresses observed within an
 * aggregated subnet.
 * 
 * Memory footprint is strictly bounded to 32 bytes (4 longs in an AtomicLongArray),
 * ensuring zero memory explosion regardless of subnet size.
 * 
 * - For IPv4 /24 subnets: Host address is mapped exactly to bit 0..255 (100% precision).
 * - For larger subnets (/16) or IPv6 (/64): Uses a fast hash modulo 256 (Linear Counting).
 * 
 * @author Henning
 */
public class AntiDoSCardinalityBitSet {

	// 256 bits = 4 * 64-bit words
	private final AtomicLongArray bits = new AtomicLongArray(4);

	/**
	 * Registers a client IP into the 256-bit tracking structure.
	 * 
	 * @param ipv4Bytes Parsed 4-byte array if IPv4 literal, or null otherwise
	 * @param ip        Raw IP string
	 * @param v4Mask    IPv4 subnet prefix length
	 * @param v6Mask    IPv6 subnet prefix length
	 */
	public void register(byte[] ipv4Bytes, String ip, int v4Mask, int v6Mask) {
		int hostBit;
		if (ipv4Bytes != null && ipv4Bytes.length == 4) {
			if (v4Mask == 24) {
				// Exact host address within /24 (0..255)
				hostBit = ipv4Bytes[3] & 0xFF;
			} else if (v4Mask < 24) {
				// /16 to /23: combine host octets and fold into 8 bits
				int hostWord = ((ipv4Bytes[2] & 0xFF) << 8) | (ipv4Bytes[3] & 0xFF);
				hostBit = (hostWord ^ (hostWord >>> 8)) & 0xFF;
			} else {
				// /25 to /31
				hostBit = ipv4Bytes[3] & 0xFF;
			}
		} else if (ip != null) {
			// IPv6 or unparsed address: fast string hash mapped to 0..255
			hostBit = (ip.hashCode() & 0x7FFFFFFF) % 256;
		} else {
			return;
		}

		int wordIndex = hostBit >>> 6; // 0..3
		long mask = 1L << (hostBit & 63);

		bits.getAndUpdate(wordIndex, current -> current | mask);
	}

	/**
	 * Returns the count of distinct client IP addresses observed.
	 * 
	 * @return Number of distinct IPs (at least 1 if any bits set, or 1 if empty)
	 */
	public int getDistinctCount() {
		int totalBits = Long.bitCount(bits.get(0))
				+ Long.bitCount(bits.get(1))
				+ Long.bitCount(bits.get(2))
				+ Long.bitCount(bits.get(3));
		return Math.max(1, totalBits);
	}
}
