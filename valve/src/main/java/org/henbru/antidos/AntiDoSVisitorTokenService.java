package org.henbru.antidos;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
 * Cryptographically authenticated, stateless visitor token service using
 * AES-256-GCM (AEAD).
 * 
 * Packs client subnet, 64-bit expiration epoch timestamp, and a saturating
 * visit counter into a compact authenticated binary payload, encoded as
 * Base64URL without padding (~58-76 characters).
 * 
 * Implements strict zero-runtime-dependency constraints using Java Standard
 * Library (java.base).
 * 
 * @author Henning
 *
 */
public final class AntiDoSVisitorTokenService {

	public static final byte TOKEN_VERSION = 1;
	public static final int GCM_IV_LENGTH_BYTES = 12;
	public static final int GCM_TAG_LENGTH_BITS = 128; // 16 bytes authentication tag
	public static final int MAX_COUNTER_VALUE = 65535;

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

	private final SecretKey secretKey;

	/**
	 * Represents the outcome of a visitor cookie validation.
	 */
	public record TokenData(Status status, int counter, long expiresAtMillis) {

		public enum Status {
			VALID,
			INVALID,
			EXPIRED,
			IP_MISMATCH
		}

		public boolean isValid() {
			return status == Status.VALID;
		}

		public static final TokenData INVALID = new TokenData(Status.INVALID, 0, 0L);
		public static final TokenData EXPIRED = new TokenData(Status.EXPIRED, 0, 0L);
		public static final TokenData IP_MISMATCH = new TokenData(Status.IP_MISMATCH, 0, 0L);

		public static TokenData valid(int counter, long expiresAtMillis) {
			return new TokenData(Status.VALID, counter, expiresAtMillis);
		}
	}

	public AntiDoSVisitorTokenService(SecretKey secretKey) {
		if (secretKey == null) {
			throw new IllegalArgumentException("SecretKey must not be null");
		}
		this.secretKey = secretKey;
	}

	/**
	 * Creates an AES-GCM encrypted and authenticated visitor cookie token.
	 * 
	 * @param subnetBytes    The masked client subnet bytes (e.g. 4 bytes for IPv4, 8/16 for IPv6)
	 * @param currentCounter The last observed counter value (0 for first contact)
	 * @param ttlMillis      Time-to-live in milliseconds
	 * @param nowMillis      Current system timestamp in milliseconds
	 * @return Base64URL encoded authenticated token string
	 */
	public String createToken(byte[] subnetBytes, int currentCounter, long ttlMillis, long nowMillis) {
		if (subnetBytes == null || subnetBytes.length == 0 || subnetBytes.length > 16) {
			throw new IllegalArgumentException("Invalid subnet bytes");
		}

		byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
		SECURE_RANDOM.nextBytes(iv);

		// Saturating counter: prevents integer overflow back to 0
		int nextCounter = currentCounter >= MAX_COUNTER_VALUE ? MAX_COUNTER_VALUE : currentCounter + 1;
		long expiresAt = nowMillis + ttlMillis;

		// Plaintext layout: [version: 1B] [ipLen: 1B] [subnetBytes: NB] [expiresAt: 8B] [counter: 2B]
		ByteBuffer plain = ByteBuffer.allocate(1 + 1 + subnetBytes.length + 8 + 2);
		plain.put(TOKEN_VERSION);
		plain.put((byte) subnetBytes.length);
		plain.put(subnetBytes);
		plain.putLong(expiresAt);
		plain.putShort((short) nextCounter);

		try {
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
			byte[] cipherTextWithTag = cipher.doFinal(plain.array());

			// Combined output: [IV (12B)] + [CipherText & Tag]
			ByteBuffer out = ByteBuffer.allocate(iv.length + cipherTextWithTag.length);
			out.put(iv);
			out.put(cipherTextWithTag);

			return Base64.getUrlEncoder().withoutPadding().encodeToString(out.array());
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Failed to encrypt visitor token", e);
		}
	}

	/**
	 * Decrypts and validates an incoming visitor cookie token.
	 * 
	 * @param cookieValue       The raw cookie value from the HTTP request
	 * @param clientSubnetBytes The current client's masked subnet bytes
	 * @param nowMillis         Current system timestamp in milliseconds
	 * @return TokenData with validation status, visit counter, and expiration
	 */
	public TokenData validateToken(String cookieValue, byte[] clientSubnetBytes, long nowMillis) {
		if (cookieValue == null || cookieValue.length() < 30 || clientSubnetBytes == null) {
			return TokenData.INVALID;
		}

		try {
			byte[] combined = Base64.getUrlDecoder().decode(cookieValue);
			// Minimum size: 12B IV + 1B ver + 1B len + 1B min subnet + 8B exp + 2B cnt + 16B tag = 41B
			if (combined.length < GCM_IV_LENGTH_BYTES + 1 + 1 + 1 + 8 + 2 + 16) {
				return TokenData.INVALID;
			}

			ByteBuffer in = ByteBuffer.wrap(combined);
			byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
			in.get(iv);
			byte[] cipherText = new byte[in.remaining()];
			in.get(cipherText);

			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
			byte[] decrypted = cipher.doFinal(cipherText); // Throws AEADBadTagException on tampering

			ByteBuffer plain = ByteBuffer.wrap(decrypted);
			byte version = plain.get();
			if (version != TOKEN_VERSION) {
				return TokenData.INVALID;
			}

			int ipLen = plain.get() & 0xFF;
			if (ipLen <= 0 || ipLen > 16 || plain.remaining() < ipLen + 8 + 2) {
				return TokenData.INVALID;
			}

			byte[] tokenSubnet = new byte[ipLen];
			plain.get(tokenSubnet);
			long expiresAt = plain.getLong();
			int counter = plain.getShort() & 0xFFFF;

			// 1. Expiration check:
			if (nowMillis > expiresAt) {
				return TokenData.EXPIRED;
			}

			// 2. Subnet binding check (constant-time):
			if (!MessageDigest.isEqual(tokenSubnet, clientSubnetBytes)) {
				return TokenData.IP_MISMATCH;
			}

			return TokenData.valid(counter, expiresAt);
		} catch (GeneralSecurityException | IllegalArgumentException | BufferUnderflowException e) {
			return TokenData.INVALID;
		}
	}

	/**
	 * Parses a secret string (hex, base64, or passphrase) into an AES SecretKey,
	 * or generates an ephemeral 256-bit AES key if the input is null or empty.
	 * 
	 * @param secret The secret string from configuration (or null/empty)
	 * @return A valid 256-bit (or 128-bit) AES SecretKey
	 */
	public static SecretKey parseOrGenerateKey(String secret) {
		if (secret == null || secret.trim().isEmpty()) {
			try {
				KeyGenerator keyGen = KeyGenerator.getInstance("AES");
				keyGen.init(256, SECURE_RANDOM);
				return keyGen.generateKey();
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException("AES algorithm unavailable", e);
			}
		}

		String trimmed = secret.trim();

		// Hex string: 64 hex chars = 32 bytes (256 bits), 32 hex chars = 16 bytes (128 bits)
		if ((trimmed.length() == 64 || trimmed.length() == 32) && isHexString(trimmed)) {
			byte[] keyBytes = parseHex(trimmed);
			return new SecretKeySpec(keyBytes, "AES");
		}

		// Base64 string: 44 chars (256-bit with padding or without) or 24 chars (128-bit)
		try {
			byte[] decoded = Base64.getDecoder().decode(trimmed);
			if (decoded.length == 32 || decoded.length == 16) {
				return new SecretKeySpec(decoded, "AES");
			}
		} catch (IllegalArgumentException ignored) {
			// Not a valid Base64 string, proceed to SHA-256 derivation
		}

		// Fallback: derive 256-bit AES key by hashing the secret with SHA-256
		try {
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			byte[] derived = sha256.digest(trimmed.getBytes(StandardCharsets.UTF_8));
			return new SecretKeySpec(derived, "AES");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 algorithm unavailable", e);
		}
	}

	private static boolean isHexString(String s) {
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			boolean isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
			if (!isHex) {
				return false;
			}
		}
		return true;
	}

	private static byte[] parseHex(String hex) {
		int len = hex.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
					+ Character.digit(hex.charAt(i + 1), 16));
		}
		return data;
	}
}
