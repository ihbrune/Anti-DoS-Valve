package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * End-to-end integration test running the Anti-DoS-Valve inside a real Apache Tomcat 10.1 container.
 *
 * <p>Validates the demo configuration defined in {@code docker/server.xml}:
 * <ul>
 *   <li>Blocking mode on {@code /valvetest} after threshold (5 requests)</li>
 *   <li>Exclusion of {@code nonRelevantPaths} on {@code /valvetest/ex}</li>
 *   <li>Marking mode on {@code /advdemo/advdemo.jsp} after threshold</li>
 *   <li>IP access restrictions on {@code /antidos-status}</li>
 * </ul>
 *
 * <p>Uses the native Java 21 {@link HttpClient} for HTTP requests.
 */
public class AntiDoSValveDockerIT {

	static {
		// Force modern Docker API version to support Docker Engine 26+, 27+ and OrbStack
		if (System.getProperty("api.version") == null) {
			System.setProperty("api.version", "1.44");
		}
	}

	private static final String TOMCAT_IMAGE = "tomcat:10.1.60-jre25-temurin-noble";
	private static final int TOMCAT_HTTP_PORT = 8080;

	private static GenericContainer<?> tomcatContainer;
	private static String baseUrl;
	private static HttpClient httpClient;

	@BeforeAll
	@SuppressWarnings("resource")
	public static void setUp() {
		// Gracefully skip if Docker is not running or accessible
		boolean dockerAvailable = false;
		try {
			dockerAvailable = DockerClientFactory.instance().isDockerAvailable();
		} catch (Throwable t) {
			// Docker daemon unreachable
		}
		Assumptions.assumeTrue(dockerAvailable,
				"Docker daemon is not available - skipping Docker integration tests.");

		Path valveJar = findBuiltValveJar();
		Assumptions.assumeTrue(Files.exists(valveJar),
				"Valve JAR not found at " + valveJar + " - run 'mvn package' first.");

		Path serverXmlPath = Files.exists(Paths.get("docker/server.xml"))
				? Paths.get("docker/server.xml")
				: Paths.get("../docker/server.xml");
		Path advdemoPath = Files.exists(Paths.get("docker/advdemo"))
				? Paths.get("docker/advdemo")
				: Paths.get("../docker/advdemo");

		tomcatContainer = new GenericContainer<>(TOMCAT_IMAGE)
				.withExposedPorts(TOMCAT_HTTP_PORT)
				.withCopyFileToContainer(
						MountableFile.forHostPath(serverXmlPath.toAbsolutePath().toString()),
						"/usr/local/tomcat/conf/server.xml")
				.withCopyFileToContainer(
						MountableFile.forHostPath(valveJar.toAbsolutePath().toString()),
						"/usr/local/tomcat/lib/anti-dos-valve.jar")
				.withCopyFileToContainer(
						MountableFile.forHostPath(advdemoPath.toAbsolutePath().toString()),
						"/usr/local/tomcat/webapps/advdemo")
				.waitingFor(Wait.forLogMessage(".*Server startup in.*\\n", 1)
						.withStartupTimeout(Duration.ofSeconds(60)));

		tomcatContainer.start();

		int mappedPort = tomcatContainer.getMappedPort(TOMCAT_HTTP_PORT);
		baseUrl = "http://localhost:" + mappedPort;
		httpClient = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(5))
				.build();
	}

	@AfterAll
	public static void tearDown() {
		if (tomcatContainer != null && tomcatContainer.isRunning()) {
			tomcatContainer.stop();
		}
	}

	@Test
	@DisplayName("Blocking Mode: /valvetest allows 5 requests, then blocks the 6th with HTTP 429")
	void testBlockingModeOnValveTestPath() throws IOException, InterruptedException {
		URI uri = URI.create(baseUrl + "/valvetest");

		// First 5 requests should pass through the valve (Tomcat returns 404 since no webapp is mapped to /valvetest)
		for (int i = 1; i <= 5; i++) {
			HttpRequest request = HttpRequest.newBuilder(uri).GET().build();
			HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
			assertEquals(404, response.statusCode(),
					"Request " + i + " should pass the valve (expecting Tomcat 404)");
		}

		// 6th request exceeds allowedRequestsPerSlot="5" -> Anti-DoS-Valve must block with 429
		HttpRequest blockedRequest = HttpRequest.newBuilder(uri).GET().build();
		HttpResponse<String> blockedResponse = httpClient.send(blockedRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(AntiDoSValve.DEFAULT_HTTP_STATUS_CODE, blockedResponse.statusCode(),
				"6th request must be blocked by AntiDoSValve with HTTP " + AntiDoSValve.DEFAULT_HTTP_STATUS_CODE);
	}

	@Test
	@DisplayName("Exclusion: /valvetest/ex is configured in nonRelevantPaths and is never blocked")
	void testNonRelevantPathsAreNeverBlocked() throws IOException, InterruptedException {
		URI uri = URI.create(baseUrl + "/valvetest/ex");

		// Send 10 requests; threshold is 5, but /valvetest/ex must be excluded
		for (int i = 1; i <= 10; i++) {
			HttpRequest request = HttpRequest.newBuilder(uri).GET().build();
			HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
			assertEquals(404, response.statusCode(),
					"Request " + i + " to non-relevant path should not be blocked");
		}
	}

	@Test
	@DisplayName("Marking Mode: /advdemo/advdemo.jsp returns HTTP 200 and marks requests once threshold is exceeded")
	void testMarkingModeOnAdvDemo() throws IOException, InterruptedException {
		URI uri = URI.create(baseUrl + "/advdemo/advdemo.jsp");

		// First 5 requests: marking threshold not yet exceeded, attribute is null
		for (int i = 1; i <= 5; i++) {
			HttpRequest request = HttpRequest.newBuilder(uri).GET().build();
			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			assertEquals(200, response.statusCode(), "Request " + i + " to advdemo.jsp should succeed");
			assertFalse(response.body().contains("MARKING-VALVE"),
					"Request " + i + " should not be marked yet");
		}

		// 6th request: exceeds threshold -> valve marks request with attribute "MARKING-VALVE", still returns 200
		HttpRequest markedRequest = HttpRequest.newBuilder(uri).GET().build();
		HttpResponse<String> markedResponse = httpClient.send(markedRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(200, markedResponse.statusCode(),
					"Marking mode should not reject request, expected HTTP 200");
		assertTrue(markedResponse.body().contains("MARKING-VALVE"),
				"Response HTML body should contain the marking attribute value 'MARKING-VALVE'");
		assertTrue(markedResponse.body().contains("<span id=\"authStatus\">false</span>"),
				"Before calling /advdemo/trust, request must be unauthenticated (AUTHENTICATED=false)");

		// 7. Call /advdemo/trust via GET to simulate SSO login callback -> issues Set-Cookie: AUTH_COOKIE=...
		URI trustUri = URI.create(baseUrl + "/advdemo/trust");
		HttpRequest loginReq = HttpRequest.newBuilder(trustUri).GET().build();
		HttpResponse<String> loginResp = httpClient.send(loginReq, HttpResponse.BodyHandlers.ofString());
		assertEquals(200, loginResp.statusCode(), "GET /advdemo/trust should succeed with HTTP 200");

		String authCookiePair = loginResp.headers().allValues("Set-Cookie").stream()
				.filter(h -> h.startsWith("AUTH_COOKIE="))
				.map(h -> h.substring(0, h.indexOf(';')))
				.findFirst()
				.orElseThrow(() -> new AssertionError("Expected Set-Cookie: AUTH_COOKIE=... from /advdemo/trust"));

		// 8. Request /advdemo/advdemo.jsp with the issued AUTH_COOKIE -> Valve sets AUTHENTICATED=true
		HttpRequest authReq = HttpRequest.newBuilder(uri)
				.header("Cookie", authCookiePair)
				.GET()
				.build();
		HttpResponse<String> authResp = httpClient.send(authReq, HttpResponse.BodyHandlers.ofString());
		assertEquals(200, authResp.statusCode());
		assertTrue(authResp.body().contains("<span id=\"authStatus\">true</span>"),
				"Authenticated request carrying valid AUTH_COOKIE must show AUTHENTICATED=true");

		// 9. Call /advdemo/trust?logout=true -> invalidates AUTH_COOKIE via Max-Age=0
		URI logoutUri = URI.create(baseUrl + "/advdemo/trust?logout=true");
		HttpRequest logoutReq = HttpRequest.newBuilder(logoutUri)
				.header("Cookie", authCookiePair)
				.GET()
				.build();
		HttpResponse<String> logoutResp = httpClient.send(logoutReq, HttpResponse.BodyHandlers.ofString());
		assertEquals(200, logoutResp.statusCode());

		// 10. Subsequent request with the old AUTH_COOKIE must again evaluate to AUTHENTICATED=false
		HttpResponse<String> postLogoutResp = httpClient.send(authReq, HttpResponse.BodyHandlers.ofString());
		assertEquals(200, postLogoutResp.statusCode());
		assertTrue(postLogoutResp.body().contains("<span id=\"authStatus\">false</span>"),
				"Request with logged-out AUTH_COOKIE must evaluate to AUTHENTICATED=false");
	}

	@Test
	@DisplayName("Security: /antidos-status denies unauthorized access without valid token (401 or 404)")
	void testStatusEndpointRestrictsUnauthorizedIPs() throws IOException, InterruptedException {
		URI uri = URI.create(baseUrl + "/antidos-status");
		HttpRequest request = HttpRequest.newBuilder(uri).GET().build();
		HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());

		// In docker/server.xml, statusAllowedIPs is set to 192.168.*.* without a static password (random token generated).
		// - If the incoming client IP matches 192.168.*.* (e.g. OrbStack / macOS local network), IP check passes,
		//   and the missing token rejects with HTTP 401 Unauthorized.
		// - If the incoming client IP does not match (e.g. default Linux Docker bridge 172.17.*.*),
		//   the IP whitelist rejects with HTTP 404 Not Found to conceal endpoint existence.
		// In both environments, unauthorized access must be rejected!
		int statusCode = response.statusCode();
		assertTrue(statusCode == 401 || statusCode == 404,
				"Status dashboard must reject unauthorized requests with 401 or 404, but was: " + statusCode);
	}

	/**
	 * Resolves the packaged valve JAR in the {@code target/} directory, ignoring shaded tomcat9 JARs.
	 */
	private static Path findBuiltValveJar() {
		Path targetDir = Paths.get("target");
		if (!Files.isDirectory(targetDir) && Files.isDirectory(Paths.get("valve/target"))) {
			targetDir = Paths.get("valve/target");
		}
		if (!Files.isDirectory(targetDir)) {
			return Paths.get("target/anti-dos-valve.jar");
		}
		try (var stream = Files.newDirectoryStream(targetDir, path -> {
			String name = path.getFileName().toString();
			return name.startsWith("anti-dos-valve-") && name.endsWith(".jar") && !name.contains("-tomcat9")
					&& !name.contains("-sources") && !name.contains("-javadoc");
		})) {
			var it = stream.iterator();
			if (it.hasNext()) {
				return it.next();
			}
		} catch (IOException e) {
			// fallback
		}
		return Paths.get("target/anti-dos-valve.jar");
	}
}
