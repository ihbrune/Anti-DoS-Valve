package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Aggregated hourly time-bucket record representing traffic statistics for a distinct endpoint (URI route) and HTTP method.
 */
public record EndpointRollup(
		Long id,
		Instant bucketStart,
		String serverId,
		String valveName,
		String cleanEndpoint,
		String sampleMethod,
		long totalRequests,
		long blockedRequests,
		long markedRequests,
		long activeRequests,
		long authenticatedRequests,
		long internalRequests,
		long crawlerRequests,
		int distinctClients,
		int distinctSubnets,
		int distinctUserAgents,
		int authSamples,
		int returningSamples
) {

	public EndpointRollup(
			Instant bucketStart,
			String serverId,
			String valveName,
			String cleanEndpoint,
			String sampleMethod,
			long totalRequests,
			long blockedRequests,
			long markedRequests,
			long activeRequests,
			long authenticatedRequests,
			long internalRequests,
			long crawlerRequests,
			int distinctClients,
			int distinctSubnets,
			int distinctUserAgents,
			int authSamples,
			int returningSamples
	) {
		this(null, bucketStart, serverId, valveName, cleanEndpoint, sampleMethod,
				totalRequests, blockedRequests, markedRequests, activeRequests,
				authenticatedRequests, internalRequests, crawlerRequests,
				distinctClients, distinctSubnets, distinctUserAgents,
				authSamples, returningSamples);
	}

	/**
	 * Canonicalizes raw URIs by stripping query parameters (?foo=bar), matrix parameters (;jsessionid=...),
	 * collapsing redundant slashes, and trimming whitespace.
	 *
	 * @param rawUri Raw sampled request URI
	 * @return Clean canonical URI path, e.g. "/portal/course/catalog"
	 */
	public static String normalizeUri(String rawUri) {
		if (rawUri == null || rawUri.isBlank()) {
			return "/";
		}
		String s = rawUri.trim();
		int q = s.indexOf('?');
		if (q >= 0) {
			s = s.substring(0, q);
		}
		int sc = s.indexOf(';');
		if (sc >= 0) {
			s = s.substring(0, sc);
		}
		if (s.isEmpty()) {
			return "/";
		}
		if (!s.startsWith("/")) {
			s = "/" + s;
		}
		// Strip trailing slash if longer than 1 char to group "/api/data/" with "/api/data"
		if (s.length() > 1 && s.endsWith("/")) {
			s = s.substring(0, s.length() - 1);
		}
		return s;
	}
}
