package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import javax.crypto.SecretKey;
import org.henbru.antidos.AntiDoSVisitorTokenService.TokenData;
import org.junit.jupiter.api.Test;

class AntiDoSVisitorTokenServiceTest {

	@Test
	void testKeyParsingVariants() {
		// 1. Hex key (64 hex chars = 32 bytes)
		String hexKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
		SecretKey k1 = AntiDoSVisitorTokenService.parseOrGenerateKey(hexKey);
		assertEquals("AES", k1.getAlgorithm());
		assertEquals(32, k1.getEncoded().length);

		// 2. Base64 key (32 bytes = 44 chars)
		byte[] raw = new byte[32];
		for (int i = 0; i < 32; i++) raw[i] = (byte) (i + 1);
		String b64 = Base64.getEncoder().encodeToString(raw);
		SecretKey k2 = AntiDoSVisitorTokenService.parseOrGenerateKey(b64);
		assertEquals("AES", k2.getAlgorithm());
		assertEquals(32, k2.getEncoded().length);
		assertArrayEquals(raw, k2.getEncoded());

		// 3. Arbitrary passphrase (hashed to 32 bytes via SHA-256)
		String passphrase = "my-secure-cluster-shared-secret-passphrase";
		SecretKey k3 = AntiDoSVisitorTokenService.parseOrGenerateKey(passphrase);
		assertEquals(32, k3.getEncoded().length);

		// 4. Ephemeral random key on null or empty
		SecretKey k4 = AntiDoSVisitorTokenService.parseOrGenerateKey(null);
		assertNotNull(k4);
		assertEquals(32, k4.getEncoded().length);

		SecretKey k5 = AntiDoSVisitorTokenService.parseOrGenerateKey("   ");
		assertNotNull(k5);
		assertEquals(32, k5.getEncoded().length);
	}

	@Test
	void testCreateAndValidateIPv4Token() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-123");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);

		byte[] subnet = new byte[]{(byte) 192, (byte) 168, 1, 0};
		long now = 1700000000000L;
		long ttl = 900_000L; // 15 minutes

		// Create token for counter = 0 (first visit -> becomes 1)
		String token = service.createToken(subnet, 0, ttl, now);
		assertNotNull(token);
		assertTrue(token.length() >= 55 && token.length() <= 65, "Expected compact token, got length: " + token.length());

		// Validate immediately with same subnet
		TokenData result = service.validateToken(token, subnet, now + 1000L);
		assertTrue(result.isValid());
		assertEquals(TokenData.Status.VALID, result.status());
		assertEquals(1, result.counter());
		assertEquals(now + ttl, result.expiresAtMillis());
	}

	@Test
	void testCounterIncrementAndSaturation() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-counter");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);
		byte[] subnet = new byte[]{10, 0, 0, 0};
		long now = 1700000000000L;

		// 1. Initial counter 0 -> becomes 1
		String t1 = service.createToken(subnet, 0, 60000, now);
		TokenData d1 = service.validateToken(t1, subnet, now);
		assertEquals(1, d1.counter());

		// 2. Next request with counter 1 -> becomes 2
		String t2 = service.createToken(subnet, d1.counter(), 60000, now);
		TokenData d2 = service.validateToken(t2, subnet, now);
		assertEquals(2, d2.counter());

		// 3. Counter saturation at MAX_COUNTER_VALUE (65535)
		String tMax = service.createToken(subnet, AntiDoSVisitorTokenService.MAX_COUNTER_VALUE, 60000, now);
		TokenData dMax = service.validateToken(tMax, subnet, now);
		assertEquals(AntiDoSVisitorTokenService.MAX_COUNTER_VALUE, dMax.counter());
	}

	@Test
	void testExpiration() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-exp");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);
		byte[] subnet = new byte[]{(byte) 172, 16, 0, 0};
		long now = 1700000000000L;
		long ttl = 60_000L; // 1 minute

		String token = service.createToken(subnet, 1, ttl, now);

		// Within TTL: valid
		assertTrue(service.validateToken(token, subnet, now + 59_000L).isValid());

		// After TTL: expired
		TokenData expiredResult = service.validateToken(token, subnet, now + 60_001L);
		assertFalse(expiredResult.isValid());
		assertEquals(TokenData.Status.EXPIRED, expiredResult.status());
	}

	@Test
	void testSubnetMismatchReplayDefense() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-ip");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);
		byte[] subnetA = new byte[]{(byte) 198, 51, 100, 0};
		byte[] subnetB = new byte[]{(byte) 203, 0, 113, 0};
		long now = 1700000000000L;

		String tokenA = service.createToken(subnetA, 1, 60000, now);

		// Valid on Subnet A
		assertTrue(service.validateToken(tokenA, subnetA, now).isValid());

		// Invalid when presented from Subnet B
		TokenData mismatchResult = service.validateToken(tokenA, subnetB, now);
		assertFalse(mismatchResult.isValid());
		assertEquals(TokenData.Status.IP_MISMATCH, mismatchResult.status());
	}

	@Test
	void testIntegrityTamperingDetection() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-tamper");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);
		byte[] subnet = new byte[]{1, 2, 3, 0};
		long now = 1700000000000L;

		String token = service.createToken(subnet, 1, 60000, now);
		byte[] raw = Base64.getUrlDecoder().decode(token);

		// Flip one bit in the middle of the ciphertext
		raw[raw.length / 2] ^= 0x01;
		String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

		TokenData result = service.validateToken(tampered, subnet, now);
		assertFalse(result.isValid());
		assertEquals(TokenData.Status.INVALID, result.status());
	}

	@Test
	void testMalformedAndNullInput() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-malformed");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);
		byte[] subnet = new byte[]{1, 2, 3, 0};

		assertEquals(TokenData.Status.INVALID, service.validateToken(null, subnet, 1000L).status());
		assertEquals(TokenData.Status.INVALID, service.validateToken("", subnet, 1000L).status());
		assertEquals(TokenData.Status.INVALID, service.validateToken("short", subnet, 1000L).status());
		assertEquals(TokenData.Status.INVALID, service.validateToken("not-base-64!@#$%", subnet, 1000L).status());
	}

	@Test
	void testStatelessMultiNodeVerification() {
		String sharedKey = "shared-cluster-key-for-multiple-tomcat-nodes";
		SecretKey kA = AntiDoSVisitorTokenService.parseOrGenerateKey(sharedKey);
		SecretKey kB = AntiDoSVisitorTokenService.parseOrGenerateKey(sharedKey);

		AntiDoSVisitorTokenService nodeA = new AntiDoSVisitorTokenService(kA);
		AntiDoSVisitorTokenService nodeB = new AntiDoSVisitorTokenService(kB);

		byte[] subnet = new byte[]{(byte) 192, 0, 2, 0};
		long now = 1700000000000L;

		// Issued on Node A
		String tokenFromNodeA = nodeA.createToken(subnet, 3, 900_000L, now);

		// Verified on Node B without any inter-server communication
		TokenData resultOnNodeB = nodeB.validateToken(tokenFromNodeA, subnet, now + 5000L);
		assertTrue(resultOnNodeB.isValid());
		assertEquals(4, resultOnNodeB.counter());
	}

	@Test
	void testIPv6TokenSupport() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-v6");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);

		// 8-byte /64 subnet prefix for 2001:db8:abcd:1234::/64
		byte[] ipv6Subnet = new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, (byte) 0xab, (byte) 0xcd, 0x12, 0x34};
		long now = 1700000000000L;

		String token = service.createToken(ipv6Subnet, 0, 60000, now);
		TokenData data = service.validateToken(token, ipv6Subnet, now);
		assertTrue(data.isValid());
		assertEquals(1, data.counter());

		// Different /64 prefix
		byte[] otherSubnet = new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, (byte) 0xab, (byte) 0xcd, 0x56, 0x78};
		assertEquals(TokenData.Status.IP_MISMATCH, service.validateToken(token, otherSubnet, now).status());
	}
}
