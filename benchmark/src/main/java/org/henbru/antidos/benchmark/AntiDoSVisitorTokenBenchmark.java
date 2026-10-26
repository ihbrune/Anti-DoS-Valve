package org.henbru.antidos.benchmark;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.henbru.antidos.AntiDoSMonitor;
import org.henbru.antidos.AntiDoSVisitorTokenService;
import org.henbru.antidos.AntiDoSVisitorTokenService.TokenData;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Dedicated JMH benchmark measuring the cryptographic throughput of the visitor cookie engine
 * ({@link AntiDoSVisitorTokenService} with AES-256-GCM / AEAD).
 * <p>
 * Measures:
 * 1. Token validation for returning visitors (AES-GCM Decrypt + AEAD authentication + TTL check).
 * 2. Token creation for first-contact / refresh (SecureRandom IV + AES-GCM Encrypt + Base64URL encode).
 * 3. Tampered token rejection (detecting AEAD integrity failure).
 * 4. Full pipeline combining token validation with monitor registration.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class AntiDoSVisitorTokenBenchmark {

	private TrafficSimulator trafficSimulator;
	private AntiDoSVisitorTokenService tokenService;
	private AntiDoSMonitor monitor;

	private byte[][] subnets;
	private String[] validTokens;
	private String[] tamperedTokens;

	@Setup
	public void setup() throws Exception {
		this.trafficSimulator = new TrafficSimulator(20_000, 42L, TrafficDistribution.ZIPF);

		// Initialize AES-256 key deterministically
		byte[] keyBytes = MessageDigest.getInstance("SHA-256")
				.digest("antidos-benchmark-secret-key-salt-2026".getBytes(StandardCharsets.UTF_8));
		SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
		this.tokenService = new AntiDoSVisitorTokenService(secretKey);

		this.monitor = new AntiDoSMonitor(
				"VisitorBenchmarkMonitor",
				20_000,
				10_000,
				10,
				60,
				100,
				0.5f
		);

		long now = System.currentTimeMillis();
		this.subnets = new byte[256][4];
		this.validTokens = new String[256];
		this.tamperedTokens = new String[256];

		for (int i = 0; i < 256; i++) {
			byte[] subnet = new byte[] { (byte) 198, (byte) 51, (byte) i, (byte) 0 };
			this.subnets[i] = subnet;
			String token = tokenService.createToken(subnet, 5, 900_000L, now);
			this.validTokens[i] = token;

			// Tamper token by mutating the last character
			char last = token.charAt(token.length() - 1);
			char flipped = (last == 'A') ? 'B' : 'A';
			this.tamperedTokens[i] = token.substring(0, token.length() - 1) + flipped;
		}
	}

	@TearDown
	public void tearDown() {
		if (monitor != null) {
			monitor.shutdown();
		}
	}

	@Benchmark
	@Threads(Threads.MAX)
	public TokenData validateToken_Valid() {
		int idx = ThreadLocalRandom.current().nextInt(256);
		byte[] subnet = subnets[idx];
		String token = validTokens[idx];
		return tokenService.validateToken(token, subnet, System.currentTimeMillis());
	}

	@Benchmark
	@Threads(Threads.MAX)
	public String createToken_New() {
		int idx = ThreadLocalRandom.current().nextInt(256);
		byte[] subnet = subnets[idx];
		return tokenService.createToken(subnet, 1, 900_000L, System.currentTimeMillis());
	}

	@Benchmark
	@Threads(Threads.MAX)
	public TokenData validateToken_Tampered() {
		int idx = ThreadLocalRandom.current().nextInt(256);
		byte[] subnet = subnets[idx];
		String token = tamperedTokens[idx];
		return tokenService.validateToken(token, subnet, System.currentTimeMillis());
	}

	@Benchmark
	@Threads(Threads.MAX)
	public boolean fullPipeline_ReturningVisitor() {
		int idx = ThreadLocalRandom.current().nextInt(256);
		byte[] subnet = subnets[idx];
		String token = validTokens[idx];
		TokenData td = tokenService.validateToken(token, subnet, System.currentTimeMillis());
		String ip = trafficSimulator.nextIp();
		return monitor.registerAndCheckRequest(ip, ip, null, false, 0, 0, td.isValid());
	}
}
