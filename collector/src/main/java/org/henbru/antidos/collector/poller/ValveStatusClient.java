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
		return fetchSlotDetails(endpoint, valveName, slotParam, limitParam, null, null);
	}

	public ValveDetailsDto fetchSlotDetails(EndpointConfig endpoint, String valveName, String slotParam,
			String limitParam, String blockedLimitParam, String activeLimitParam)
			throws IOException, InterruptedException {
		return fetchSlotDetails(endpoint, valveName, slotParam, limitParam, blockedLimitParam, activeLimitParam, null, null, null);
	}

	public ValveDetailsDto fetchSlotDetails(EndpointConfig endpoint, String valveName, String slotParam,
			String limitParam, String blockedLimitParam, String activeLimitParam,
			Long sinceBlockedOrder, Long sinceActiveOrder, Integer activeMinCount)
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
		if (blockedLimitParam != null && !blockedLimitParam.trim().isEmpty()) {
			sb.append("&blockedLimit=").append(URLEncoder.encode(blockedLimitParam.trim(), StandardCharsets.UTF_8));
		}
		if (activeLimitParam != null && !activeLimitParam.trim().isEmpty()) {
			sb.append("&activeLimit=").append(URLEncoder.encode(activeLimitParam.trim(), StandardCharsets.UTF_8));
		}
		if (sinceBlockedOrder != null) {
			sb.append("&sinceBlockedOrder=").append(sinceBlockedOrder);
		}
		if (sinceActiveOrder != null) {
			sb.append("&sinceActiveOrder=").append(sinceActiveOrder);
		}
		if (activeMinCount != null) {
			sb.append("&activeMinCount=").append(activeMinCount);
		}

		return executeGet(endpoint, sb.toString(), ValveDetailsDto.class);
	}

	@com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
	public record MitigationCommandResponse(
			String status,
			String valve,
			String action,
			int dynamicBlocksActiveCount,
			long dynamicRulesRevision,
			long dynamicBlocksBlockedRequests
	) {
		public MitigationCommandResponse(String status, String action, String valve, int activeCount, long revision, String error) {
			this(status, valve, action, activeCount, revision, 0L);
		}

		public int activeCount() {
			return dynamicBlocksActiveCount;
		}

		public long revision() {
			return dynamicRulesRevision;
		}
	}

	public MitigationCommandResponse sendMitigationCommand(
			String targetUrl,
			String mitigationToken,
			String valveName,
			String action,
			String cidr,
			Integer ttlSeconds,
			String reason,
			String blocksPayload) throws IOException, InterruptedException {
		java.util.Map<String, String> params = new java.util.LinkedHashMap<>();
		if (action != null) params.put("action", action);
		if (cidr != null) params.put("cidr", cidr);
		if (ttlSeconds != null) params.put("ttlSeconds", String.valueOf(ttlSeconds));
		if (reason != null) params.put("reason", reason);
		if (blocksPayload != null) params.put("blocks", blocksPayload);
		return sendMitigationCommand(targetUrl, mitigationToken, valveName, params);
	}

	/**
	 * Sends a dynamic CIDR mitigation command (POST) to the target Valve endpoint.
	 *
	 * @param targetUrl       Target mitigation URL (either dedicated mitigationUrl or endpoint statusUrl)
	 * @param mitigationToken Write token configured for mitigation
	 * @param valveName       Optional target valve name
	 * @param formParams      Key-value parameters for application/x-www-form-urlencoded body
	 */
	public MitigationCommandResponse sendMitigationCommand(
			String targetUrl,
			String mitigationToken,
			String valveName,
			java.util.Map<String, String> formParams) throws IOException, InterruptedException {
		String base = cleanBaseUrl(targetUrl);
		StringBuilder body = new StringBuilder();
		if (valveName != null && !valveName.isBlank()) {
			body.append("valve=").append(URLEncoder.encode(valveName.trim(), StandardCharsets.UTF_8));
		}
		if (formParams != null) {
			for (java.util.Map.Entry<String, String> entry : formParams.entrySet()) {
				if (entry.getKey() == null || entry.getValue() == null) {
					continue;
				}
				if (body.length() > 0) {
					body.append('&');
				}
				body.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
						.append('=')
						.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
			}
		}

		HttpRequest.Builder builder = HttpRequest.newBuilder()
				.uri(URI.create(base))
				.timeout(Duration.ofSeconds(10))
				.header("Accept", "application/json")
				.header("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");

		if (mitigationToken != null && !mitigationToken.trim().isEmpty()) {
			builder.header("Authorization", "Bearer " + mitigationToken.trim());
		}

		HttpRequest request = builder.POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)).build();
		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

		if (response.statusCode() == 401 || response.statusCode() == 403) {
			throw new IOException("HTTP " + response.statusCode() + " Unauthorized: Invalid or missing mitigation token for " + base);
		}
		if (response.statusCode() == 404) {
			throw new IOException("HTTP 404 Not Found: Mitigation endpoint unavailable or blocked by IP filter at " + base);
		}
		if (response.statusCode() == 400) {
			throw new IOException("HTTP 400 Bad Request from " + base + ": " + response.body());
		}
		if (response.statusCode() != 200) {
			throw new IOException("HTTP " + response.statusCode() + " response from " + base);
		}

		return objectMapper.readValue(response.body(), MitigationCommandResponse.class);
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
