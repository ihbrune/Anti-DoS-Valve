package org.henbru.antidos.collector.poller;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.springframework.stereotype.Component;

/**
 * HTTP client for fetching JSON status telemetry from AntiDoSValve endpoints.
 */
@Component
public class ValveStatusClient {

	private final HttpClient httpClient;
	private final ObjectMapper objectMapper;

	public ValveStatusClient(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
		this.httpClient = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(5))
				.followRedirects(HttpClient.Redirect.NORMAL)
				.build();
	}

	public ValveOverviewDto fetchOverview(EndpointConfig endpoint) throws IOException, InterruptedException {
		String base = cleanBaseUrl(endpoint.getUrl());
		String targetUrl = base + "?format=json";
		return executeGet(endpoint, targetUrl, ValveOverviewDto.class);
	}

	public ValveDetailsDto fetchSlotDetails(EndpointConfig endpoint, String valveName, String slotParam, String limitParam)
			throws IOException, InterruptedException {
		String base = cleanBaseUrl(endpoint.getUrl());
		StringBuilder sb = new StringBuilder(base);
		sb.append("?view=details&format=json");
		if (valveName != null && !valveName.trim().isEmpty()) {
			sb.append("&valve=").append(URLEncoder.encode(valveName.trim(), StandardCharsets.UTF_8));
		}
		if (slotParam != null && !slotParam.trim().isEmpty()) {
			sb.append("&slot=").append(URLEncoder.encode(slotParam.trim(), StandardCharsets.UTF_8));
		}
		if (limitParam != null && !limitParam.trim().isEmpty()) {
			sb.append("&limit=").append(URLEncoder.encode(limitParam.trim(), StandardCharsets.UTF_8));
		}

		return executeGet(endpoint, sb.toString(), ValveDetailsDto.class);
	}

	private <T> T executeGet(EndpointConfig endpoint, String url, Class<T> targetClass)
			throws IOException, InterruptedException {
		HttpRequest.Builder builder = HttpRequest.newBuilder()
				.uri(URI.create(url))
				.timeout(Duration.ofSeconds(10))
				.header("Accept", "application/json");

		if (endpoint.getToken() != null && !endpoint.getToken().trim().isEmpty()) {
			builder.header("Authorization", "Bearer " + endpoint.getToken().trim());
		}

		HttpRequest request = builder.GET().build();
		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

		if (response.statusCode() == 401 || response.statusCode() == 403) {
			throw new IOException("HTTP " + response.statusCode() + " Unauthorized: Invalid or missing token for " + endpoint.getName());
		}
		if (response.statusCode() == 404) {
			throw new IOException("HTTP 404 Not Found: Status endpoint unavailable or blocked by IP filter for " + endpoint.getName());
		}
		if (response.statusCode() != 200) {
			throw new IOException("HTTP " + response.statusCode() + " response from " + endpoint.getName());
		}

		return objectMapper.readValue(response.body(), targetClass);
	}

	private static String cleanBaseUrl(String url) {
		if (url == null) {
			return "";
		}
		int queryIdx = url.indexOf('?');
		return queryIdx >= 0 ? url.substring(0, queryIdx) : url;
	}

	/**
	 * Formats any network or HTTP exception into a clear, operator-friendly diagnostic message.
	 */
	public static String formatErrorMessage(Throwable t) {
		if (t == null) {
			return "Unknown error";
		}
		Throwable current = t;
		Throwable root = t;
		while (current != null) {
			root = current;
			if (current instanceof java.net.ConnectException) {
				String msg = current.getMessage();
				return "Connection refused - server not reachable or port incorrect"
						+ (msg != null && !msg.isBlank() && !"Connection refused".equalsIgnoreCase(msg.trim()) ? " (" + msg + ")" : "");
			}
			if (current instanceof java.net.http.HttpConnectTimeoutException || current instanceof java.net.http.HttpTimeoutException) {
				return "Connection timed out - host unreachable or firewall dropped request";
			}
			if (current instanceof java.net.UnknownHostException) {
				String host = current.getMessage();
				return "Host not found: " + (host != null && !host.isBlank() ? host : "DNS resolution failed");
			}
			if (current instanceof javax.net.ssl.SSLException) {
				String msg = current.getMessage();
				return "SSL/TLS handshake error: " + (msg != null && !msg.isBlank() ? msg : "certificate invalid or HTTPS on HTTP port");
			}
			current = current.getCause();
		}

		String msg = t.getMessage();
		if (msg == null || msg.trim().isEmpty() || "null".equalsIgnoreCase(msg.trim())) {
			if (root != t && root.getMessage() != null && !root.getMessage().trim().isEmpty() && !"null".equalsIgnoreCase(root.getMessage().trim())) {
				msg = root.getMessage();
			} else {
				msg = root.getClass().getSimpleName();
			}
		}
		return msg;
	}
}
