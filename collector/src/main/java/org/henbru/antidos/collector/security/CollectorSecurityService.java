package org.henbru.antidos.collector.security;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.CollectorTokenRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Provides multi-token constant-time validation, HMAC-SHA256 browser session signing,
 * and lock-free brute-force IP lockout tracking for Collector HTTP/API access.
 */
@Service
public class CollectorSecurityService {

	private static final Logger log = LoggerFactory.getLogger(CollectorSecurityService.class);

	public static final String SESSION_COOKIE_NAME = "_adc_session";
	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private static final int MAX_FAILURE_MAP_SIZE = 10_000;

	private record AuthAttemptState(long windowStartMillis, int failures, long lockedUntilMillis) {}

	private final CollectorProperties properties;
	private final byte[] sessionSigningKey;
	private final ConcurrentHashMap<String, AuthAttemptState> failureTracker = new ConcurrentHashMap<>();

	public CollectorSecurityService(CollectorProperties properties) {
		this.properties = properties;
		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);
		this.sessionSigningKey = key;
	}

	public boolean hasConfiguredTokens() {
		List<CollectorProperties.TokenEntry> tokens = properties.getSecurity().getTokens();
		if (tokens == null || tokens.isEmpty()) {
			return false;
		}
		for (CollectorProperties.TokenEntry entry : tokens) {
			if (entry != null && entry.isEnabled() && entry.getToken() != null && !entry.getToken().isBlank()) {
				return true;
			}
		}
		return false;
	}

	public Optional<CollectorAuthContext.AuthPrincipal> authenticateToken(String rawToken) {
		if (rawToken == null || rawToken.isBlank()) {
			return Optional.empty();
		}
		byte[] providedBytes = rawToken.trim().getBytes(StandardCharsets.UTF_8);
		CollectorProperties.TokenEntry matchedEntry = null;
		int matchIndex = 0;
		int idx = 0;

		for (CollectorProperties.TokenEntry entry : properties.getSecurity().getTokens()) {
			idx++;
			if (entry == null || !entry.isEnabled() || entry.getToken() == null || entry.getToken().isBlank()) {
				continue;
			}
			byte[] expectedBytes = entry.getToken().trim().getBytes(StandardCharsets.UTF_8);
			boolean match = MessageDigest.isEqual(providedBytes, expectedBytes);
			if (match && matchedEntry == null) {
				matchedEntry = entry;
				matchIndex = idx;
			}
		}

		if (matchedEntry == null) {
			return Optional.empty();
		}
		String effectiveName = (matchedEntry.getName() != null && !matchedEntry.getName().isBlank())
				? matchedEntry.getName().trim()
				: "token-" + matchIndex;
		return Optional.of(new CollectorAuthContext.AuthPrincipal(
				effectiveName,
				matchedEntry.getRole(),
				true,
				false));
	}

	public String createSessionCookieValue(String principalName, CollectorTokenRole role) {
		String safeName = (principalName != null && !principalName.isBlank()) ? principalName.trim() : "local";
		CollectorTokenRole effectiveRole = role != null ? role : CollectorTokenRole.VIEWER;
		long expiresAtEpochSec = Instant.now().getEpochSecond() + properties.getSecurity().getSessionTtlSeconds();

		String encodedName = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(safeName.getBytes(StandardCharsets.UTF_8));
		String payload = encodedName + ":" + effectiveRole.name() + ":" + expiresAtEpochSec;
		String encodedPayload = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
		String signature = signPayload(encodedPayload);
		return encodedPayload + "." + signature;
	}

	public Optional<CollectorAuthContext.AuthPrincipal> authenticateSessionCookie(String cookieValue) {
		if (cookieValue == null || cookieValue.isBlank()) {
			return Optional.empty();
		}
		int dotIdx = cookieValue.indexOf('.');
		if (dotIdx <= 0 || dotIdx >= cookieValue.length() - 1) {
			return Optional.empty();
		}
		String encodedPayload = cookieValue.substring(0, dotIdx);
		String providedSig = cookieValue.substring(dotIdx + 1);
		String expectedSig = signPayload(encodedPayload);

		if (!MessageDigest.isEqual(
				providedSig.getBytes(StandardCharsets.UTF_8),
				expectedSig.getBytes(StandardCharsets.UTF_8))) {
			return Optional.empty();
		}

		try {
			String payload = new String(Base64.getUrlDecoder().decode(encodedPayload), StandardCharsets.UTF_8);
			String[] parts = payload.split(":", 3);
			if (parts.length != 3) {
				return Optional.empty();
			}
			String name = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
			CollectorTokenRole role = CollectorTokenRole.fromString(parts[1]);
			long expiresAtEpochSec = Long.parseLong(parts[2]);

			if (Instant.now().getEpochSecond() > expiresAtEpochSec) {
				return Optional.empty();
			}

			if (hasConfiguredTokens() && !isTokenEntryStillActive(name, role)) {
				return Optional.empty();
			}

			return Optional.of(new CollectorAuthContext.AuthPrincipal(name, role, false, true));
		} catch (Exception e) {
			return Optional.empty();
		}
	}

	private boolean isTokenEntryStillActive(String name, CollectorTokenRole role) {
		int idx = 0;
		for (CollectorProperties.TokenEntry entry : properties.getSecurity().getTokens()) {
			idx++;
			if (entry == null || !entry.isEnabled() || entry.getToken() == null || entry.getToken().isBlank()) {
				continue;
			}
			String entryName = (entry.getName() != null && !entry.getName().isBlank())
					? entry.getName().trim()
					: "token-" + idx;
			if (entryName.equals(name) && entry.getRole() == role) {
				return true;
			}
		}
		return false;
	}

	private String signPayload(String encodedPayload) {
		try {
			Mac mac = Mac.getInstance(HMAC_ALGORITHM);
			mac.init(new SecretKeySpec(sessionSigningKey, HMAC_ALGORITHM));
			byte[] rawHmac = mac.doFinal(encodedPayload.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(rawHmac);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalStateException("Failed to sign collector session cookie", e);
		}
	}

	public boolean isIpLockedOut(String clientIp) {
		if (clientIp == null || clientIp.isBlank()) {
			return false;
		}
		AuthAttemptState state = failureTracker.get(clientIp);
		if (state == null) {
			return false;
		}
		long now = System.currentTimeMillis();
		if (state.lockedUntilMillis() > now) {
			return true;
		}
		long windowMs = properties.getSecurity().getAuthLockoutSeconds() * 1000L;
		if (now - state.windowStartMillis() > windowMs) {
			failureTracker.remove(clientIp, state);
		}
		return false;
	}

	public boolean recordAuthFailure(String clientIp) {
		if (clientIp == null || clientIp.isBlank()) {
			return false;
		}
		long now = System.currentTimeMillis();
		long lockoutMs = properties.getSecurity().getAuthLockoutSeconds() * 1000L;
		int maxFailures = properties.getSecurity().getMaxAuthFailures();

		if (failureTracker.size() > MAX_FAILURE_MAP_SIZE) {
			failureTracker.entrySet().removeIf(e ->
					e.getValue().lockedUntilMillis() <= now && (now - e.getValue().windowStartMillis()) > lockoutMs);
		}

		AuthAttemptState updated = failureTracker.compute(clientIp, (ip, prev) -> {
			if (prev == null || (now - prev.windowStartMillis() > lockoutMs && prev.lockedUntilMillis() <= now)) {
				long lockedUntil = maxFailures <= 1 ? now + lockoutMs : 0L;
				return new AuthAttemptState(now, 1, lockedUntil);
			}
			int nextCount = prev.failures() + 1;
			long lockedUntil = prev.lockedUntilMillis();
			if (nextCount >= maxFailures) {
				lockedUntil = Math.max(lockedUntil, now + lockoutMs);
			}
			return new AuthAttemptState(prev.windowStartMillis(), nextCount, lockedUntil);
		});

		boolean locked = updated != null && updated.lockedUntilMillis() > now;
		if (locked) {
			log.warn("Collector auth lockout triggered for IP {} after {} failed attempts (lockout {}s).",
					clientIp, updated.failures(), properties.getSecurity().getAuthLockoutSeconds());
		}
		return locked;
	}

	public void clearAuthFailures(String clientIp) {
		if (clientIp != null && !clientIp.isBlank()) {
			failureTracker.remove(clientIp);
		}
	}

	public void clearAllFailures() {
		failureTracker.clear();
	}

	public static boolean isLoopbackAddress(String remoteAddr) {
		if (remoteAddr == null || remoteAddr.isBlank()) {
			return false;
		}
		try {
			return InetAddress.getByName(remoteAddr.trim()).isLoopbackAddress();
		} catch (Exception e) {
			return false;
		}
	}
}
