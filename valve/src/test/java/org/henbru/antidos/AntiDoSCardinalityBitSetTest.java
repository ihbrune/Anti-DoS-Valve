package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class AntiDoSCardinalityBitSetTest {

	@Test
	void testExactIPv4Subnet24Cardinality() {
		AntiDoSCardinalityBitSet bitSet = new AntiDoSCardinalityBitSet();
		assertEquals(1, bitSet.getDistinctCount());

		// 192.168.1.10
		byte[] b1 = new byte[] { (byte) 192, (byte) 168, 1, 10 };
		bitSet.register(b1, "192.168.1.10", 24, 128);
		assertEquals(1, bitSet.getDistinctCount());

		// Same IP again -> idempotent
		bitSet.register(b1, "192.168.1.10", 24, 128);
		assertEquals(1, bitSet.getDistinctCount());

		// 192.168.1.11
		byte[] b2 = new byte[] { (byte) 192, (byte) 168, 1, 11 };
		bitSet.register(b2, "192.168.1.11", 24, 128);
		assertEquals(2, bitSet.getDistinctCount());

		// Add 50 distinct IPs
		for (int i = 20; i < 70; i++) {
			byte[] b = new byte[] { (byte) 192, (byte) 168, 1, (byte) i };
			bitSet.register(b, "192.168.1." + i, 24, 128);
		}
		assertEquals(52, bitSet.getDistinctCount());
	}

	@Test
	void testIPv6OrHashFallback() {
		AntiDoSCardinalityBitSet bitSet = new AntiDoSCardinalityBitSet();

		bitSet.register(null, "2001:db8::1", 32, 64);
		bitSet.register(null, "2001:db8::1", 32, 64);
		assertEquals(1, bitSet.getDistinctCount());

		bitSet.register(null, "2001:db8::2", 32, 64);
		assertEquals(2, bitSet.getDistinctCount());
	}
}
