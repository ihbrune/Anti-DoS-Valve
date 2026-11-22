package org.henbru.antidos.collector.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.Locale;

/**
 * DTO representing host, JVM, and Tomcat connector resource utilization metrics
 * collected by an AntiDoSValve endpoint.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SystemMetricsDto(
		Double processCpuLoad,
		Double systemCpuLoad,
		Double systemLoadAverage,
		Long heapUsedBytes,
		Long heapMaxBytes,
		Double heapUsedPercent,
		Long gcCollectionCount,
		Long gcCollectionTimeMs,
		Integer tomcatBusyThreads,
		Integer tomcatMaxThreads
) {

	public boolean hasAnyMetrics() {
		return processCpuLoad != null || heapUsedPercent != null || tomcatBusyThreads != null || gcCollectionTimeMs != null;
	}

	public String formattedProcessCpu() {
		if (processCpuLoad == null) {
			return "N/A";
		}
		return String.format(Locale.US, "%.1f%%", processCpuLoad * 100.0);
	}

	public String formattedSystemCpu() {
		if (systemCpuLoad == null) {
			return "N/A";
		}
		return String.format(Locale.US, "%.1f%%", systemCpuLoad * 100.0);
	}

	public String formattedHeapPercent() {
		if (heapUsedPercent == null) {
			return "N/A";
		}
		return String.format(Locale.US, "%.1f%%", heapUsedPercent);
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
}
