package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.List;

/**
 * Forensic drilldown model for a specific User-Agent string, combining persistent memory,
 * dual status (manual override vs. live automatic 3-pillar heuristic), top origins, and
 * chronological hourly evaluation history.
 */
public record UserAgentDrilldownDto(
		String userAgent,
		String userAgentHash,
		int uaHash32,
		UserAgentFamily family,
		BrowserVersionLagAssessment versionAssessment,
		Integer parsedMajorVersion,
		Integer versionLagMajors,
		Instant firstSeenAt,
		Instant lastSeenAt,
		int lookbackHours,
		UserAgentManualOverride manualOverride,
		String operatorNote,
		String updatedBy,
		Instant updatedAt,
		UserAgentAutoVerdict liveAutoVerdict,
		String liveAutoReason,
		long totalRequests,
		int eventCount,
		long blockedRequests,
		long markedRequests,
		int distinctSubnets,
		int distinctAsns,
		double internalRatioPct,
		long internalRequests,
		double searchEngineRatioPct,
		double sampleAuthRatioPct,
		int authSamples,
		double slotAuthRatioPct,
		long authRequests,
		double incidentEventRatioPct,
		double mitigatedAsnRatioPct,
		double uaMismatchRatioPct,
		double datacenterRatioPct,
		double avgRequestsPerSlot,
		EffectiveUaHeuristicSettings thresholds,
		List<UserAgentOriginSummary> topOrigins,
		List<UserAgentHourlyPoint> hourlyHistory,
		boolean historyFromLiveEvents
) {
	public String hexHash32() {
		return String.format("0x%08x", uaHash32);
	}

	public boolean hasManualOverride() {
		return manualOverride != null && manualOverride.isManual();
	}

	public boolean isEffectiveSuspicious() {
		UserAgentManualOverride ov = manualOverride != null ? manualOverride : UserAgentManualOverride.AUTO;
		return ov.isEffectiveSuspicious(liveAutoVerdict);
	}

	public boolean isEffectiveProtected() {
		UserAgentManualOverride ov = manualOverride != null ? manualOverride : UserAgentManualOverride.AUTO;
		return ov.isEffectiveProtected(liveAutoVerdict);
	}
}
