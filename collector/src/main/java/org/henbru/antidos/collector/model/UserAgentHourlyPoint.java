package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Hourly telemetry and historical heuristic evaluation snapshot stored in {@code user_agent_hourly_rollups}.
 */
public record UserAgentHourlyPoint(
		Instant bucketStart,
		Instant bucketEnd,
		long totalRequests,
		int eventCount,
		long blockedRequests,
		long markedRequests,
		int incidentEvents,
		int authenticatedSamples,
		long authenticatedRequests,
		long internalRequests,
		long crawlerRequests,
		long datacenterRequests,
		long residentialRequests,
		long returningRequests,
		long uaMismatchRequests,
		int distinctSubnets,
		int distinctAsns,
		UserAgentAutoVerdict evaluatedVerdict,
		String evaluatedPillar,
		String evaluatedReason
) {
	private static final DateTimeFormatter HOUR_FMT = DateTimeFormatter.ofPattern("dd.MM. HH:mm");

	public String hourLabel() {
		return bucketStart != null ? HOUR_FMT.format(bucketStart.atZone(ZoneId.systemDefault())) : "—";
	}

	public double incidentEventRatioPct() {
		return eventCount > 0 ? Math.round((incidentEvents * 1000.0) / eventCount) / 10.0 : 0.0;
	}

	public double sampleAuthRatioPct() {
		return eventCount > 0 ? Math.round((authenticatedSamples * 1000.0) / eventCount) / 10.0 : 0.0;
	}

	public double avgRequestsPerSlot() {
		return eventCount > 0 ? Math.round((totalRequests * 10.0) / eventCount) / 10.0 : 0.0;
	}

	public double internalRatioPct() {
		return totalRequests > 0 ? Math.round((internalRequests * 1000.0) / totalRequests) / 10.0 : 0.0;
	}

	public double datacenterRatioPct() {
		return totalRequests > 0 ? Math.round((datacenterRequests * 1000.0) / totalRequests) / 10.0 : 0.0;
	}

	public UserAgentAutoVerdict safeVerdict() {
		return evaluatedVerdict != null ? evaluatedVerdict : UserAgentAutoVerdict.NEUTRAL;
	}
}
