package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.Locale;

/**
 * Health, connectivity, and system resource status of a monitored AntiDoSValve endpoint.
 */
public record EndpointHeartbeat(
		String serverId,
		String url,
		boolean online,
		Instant lastPollAt,
		Instant lastSuccessAt,
		String lastError,
		long responseTimeMs,
		int valvesCount,
		Double processCpuLoad,
		Double systemCpuLoad,
		Double systemLoadAverage,
		Long heapUsedBytes,
		Long heapMaxBytes,
		Double heapUsedPercent,
		Long gcCollectionTimeMs,
		Integer tomcatBusyThreads,
		Integer tomcatMaxThreads
) {
	/**
	 * Backward-compatible constructor for previous 8-parameter signature.
	 */
	public EndpointHeartbeat(
			String serverId,
			String url,
			boolean online,
			Instant lastPollAt,
			Instant lastSuccessAt,
			String lastError,
			long responseTimeMs,
			int valvesCount
	) {
		this(serverId, url, online, lastPollAt, lastSuccessAt, lastError, responseTimeMs, valvesCount,
				null, null, null, null, null, null, null, null, null);
	}

	public static EndpointHeartbeat initial(String serverId, String url) {
		return new EndpointHeartbeat(serverId, url, false, null, null, null, 0, 0);
	}

	public EndpointHeartbeat success(Instant now, long responseTimeMs, int valvesCount) {
		return new EndpointHeartbeat(serverId, url, true, now, now, null, responseTimeMs, valvesCount,
				processCpuLoad, systemCpuLoad, systemLoadAverage, heapUsedBytes, heapMaxBytes,
				heapUsedPercent, gcCollectionTimeMs, tomcatBusyThreads, tomcatMaxThreads);
	}

	public EndpointHeartbeat failure(Instant now, String error) {
		return new EndpointHeartbeat(serverId, url, false, now, lastSuccessAt, error, 0, valvesCount,
				null, null, null, null, null, null, null, null, null);
	}

	public boolean hasSystemMetrics() {
		return processCpuLoad != null || heapUsedPercent != null || tomcatBusyThreads != null;
	}

	public String formattedCpu() {
		if (processCpuLoad == null) {
			return "N/A";
		}
		return String.format(Locale.US, "%.0f%%", processCpuLoad * 100.0);
	}

	public String formattedHeap() {
		if (heapUsedPercent == null) {
			return "N/A";
		}
		return String.format(Locale.US, "%.0f%%", heapUsedPercent);
	}

	public String formattedThreads() {
		if (tomcatBusyThreads == null) {
			return "N/A";
		}
		if (tomcatMaxThreads == null) {
			return String.valueOf(tomcatBusyThreads);
		}
		return tomcatBusyThreads + " / " + tomcatMaxThreads;
	}

	public String formattedSystemCpuAndLoad() {
		if (systemCpuLoad == null && systemLoadAverage == null) {
			return "N/A";
		}
		StringBuilder sb = new StringBuilder();
		if (systemCpuLoad != null) {
			sb.append(String.format(Locale.US, "%.0f%%", systemCpuLoad * 100.0));
		}
		if (systemLoadAverage != null) {
			if (sb.length() > 0) {
				sb.append(" (Load ").append(String.format(Locale.US, "%.2f", systemLoadAverage)).append(")");
			} else {
				sb.append("Load ").append(String.format(Locale.US, "%.2f", systemLoadAverage));
			}
		}
		return sb.toString();
	}

	public String formattedHeapDetails() {
		if (heapUsedPercent == null) {
			return "N/A";
		}
		StringBuilder sb = new StringBuilder(String.format(Locale.US, "%.0f%%", heapUsedPercent));
		if (heapUsedBytes != null && heapMaxBytes != null && heapMaxBytes > 0) {
			sb.append(" (").append(heapUsedBytes / 1048576).append(" MB / ")
					.append(heapMaxBytes / 1048576).append(" MB)");
		}
		return sb.toString();
	}

	public String formattedGcPauseTime() {
		if (gcCollectionTimeMs == null) {
			return "N/A";
		}
		return gcCollectionTimeMs + " ms";
	}
}
