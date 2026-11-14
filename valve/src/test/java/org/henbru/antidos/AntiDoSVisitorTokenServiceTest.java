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

	@Test
	void testUserAgentHashMatchingAndMismatchModes() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-ua");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);
		byte[] subnet = new byte[]{(byte) 192, (byte) 168, 1, 0};
		long now = 1700000000000L;
		long ttl = 900_000L;

		String uaChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
		String uaFirefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0";
		int uaHashChrome = AntiDoSVisitorTokenService.computeUserAgentHash32(uaChrome);
		int uaHashFirefox = AntiDoSVisitorTokenService.computeUserAgentHash32(uaFirefox);
		assertNotEquals(0, uaHashChrome);
		assertNotEquals(0, uaHashFirefox);
		assertNotEquals(uaHashChrome, uaHashFirefox);

		// Issue V2 token bound to Chrome UA
		String token = service.createToken(subnet, uaHashChrome, 0, ttl, now);

		// 1. Same UA -> Valid, no mismatch
		TokenData match = service.validateToken(token, subnet, uaHashChrome, true, now + 1000L);
		assertTrue(match.isValid());
		assertEquals(TokenData.Status.VALID, match.status());
		assertFalse(match.uaMismatch());
		assertEquals(1, match.counter());

		// 2. Different UA with enforceUserAgent = false -> Valid, but uaMismatch flagged
		TokenData mismatchPermissive = service.validateToken(token, subnet, uaHashFirefox, false, now + 1000L);
		assertTrue(mismatchPermissive.isValid());
		assertEquals(TokenData.Status.VALID, mismatchPermissive.status());
		assertTrue(mismatchPermissive.uaMismatch());
		assertEquals(1, mismatchPermissive.counter());

		// 3. Different UA with enforceUserAgent = true -> Invalid (Status.UA_MISMATCH), rejected as returning visitor
		TokenData mismatchEnforced = service.validateToken(token, subnet, uaHashFirefox, true, now + 1000L);
		assertFalse(mismatchEnforced.isValid());
		assertEquals(TokenData.Status.UA_MISMATCH, mismatchEnforced.status());
		assertTrue(mismatchEnforced.uaMismatch());
	}

	@Test
	void testLegacyV1TokenBackwardCompatibility() throws Exception {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey("test-secret-key-v1-compat");
		AntiDoSVisitorTokenService service = new AntiDoSVisitorTokenService(key);
		byte[] subnet = new byte[]{(byte) 10, 0, 0, 0};
		long now = 1700000000000L;
		long ttl = 600_000L;
		long expiresAt = now + ttl;
		int counter = 5;

		// Craft a raw V1 token: [ver:1][ipLen:4][subnet:4B][exp:8B][counter:2B]
		byte[] plaintextV1 = new byte[1 + 1 + subnet.length + 8 + 2];
		plaintextV1[0] = 1; // TOKEN_VERSION_V1
		plaintextV1[1] = (byte) subnet.length;
		System.arraycopy(subnet, 0, plaintextV1, 2, subnet.length);
		int off = 2 + subnet.length;
		for (int i = 7; i >= 0; i--) {
			plaintextV1[off++] = (byte) (expiresAt >>> (i * 8));
		}
		plaintextV1[off++] = (byte) ((counter + 1) >>> 8);
		plaintextV1[off] = (byte) (counter + 1);

		// Encrypt with AES-GCM
		byte[] iv = new byte[12];
		for (int i = 0; i < iv.length; i++) iv[i] = (byte) (i + 1);
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, iv));
		byte[] ciphertext = cipher.doFinal(plaintextV1);

		byte[] rawV1Token = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, rawV1Token, 0, iv.length);
		System.arraycopy(ciphertext, 0, rawV1Token, iv.length, ciphertext.length);
		String v1TokenString = Base64.getUrlEncoder().withoutPadding().encodeToString(rawV1Token);

		// Validate V1 token in V2 service with enforceUserAgent = true
		int anyUaHash = AntiDoSVisitorTokenService.computeUserAgentHash32("Some User Agent");
		TokenData v1Result = service.validateToken(v1TokenString, subnet, anyUaHash, true, now + 1000L);

		assertTrue(v1Result.isValid(), "V1 token should be accepted as valid by V2 service");
		assertEquals(TokenData.Status.VALID, v1Result.status());
		assertFalse(v1Result.uaMismatch(), "V1 token has no UA hash, so uaMismatch must be false");
		assertEquals(6, v1Result.counter());
		assertEquals(expiresAt, v1Result.expiresAtMillis());
	}

	@Test
	void testComputeUserAgentHash32DeterministicAndNormalized() {
		assertEquals(0, AntiDoSVisitorTokenService.computeUserAgentHash32(null));
		assertEquals(0, AntiDoSVisitorTokenService.computeUserAgentHash32(""));
		assertEquals(0, AntiDoSVisitorTokenService.computeUserAgentHash32("   "));

		String ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";
		int h1 = AntiDoSVisitorTokenService.computeUserAgentHash32(ua);
		int h2 = AntiDoSVisitorTokenService.computeUserAgentHash32("  " + ua + "  ");
		assertEquals(h1, h2);
		assertNotEquals(0, h1);
	}
}
