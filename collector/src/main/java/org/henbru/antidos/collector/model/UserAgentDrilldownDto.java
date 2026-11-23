package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

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
		boolean historyFromLiveEvents,
		List<MitigationUaRule> mitigationRules
) {
	public UserAgentDrilldownDto(
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
		this(userAgent, userAgentHash, uaHash32, family, versionAssessment, parsedMajorVersion,
				versionLagMajors, firstSeenAt, lastSeenAt, lookbackHours, manualOverride,
				operatorNote, updatedBy, updatedAt, liveAutoVerdict, liveAutoReason,
				totalRequests, eventCount, blockedRequests, markedRequests, distinctSubnets,
				distinctAsns, internalRatioPct, internalRequests, searchEngineRatioPct,
				sampleAuthRatioPct, authSamples, slotAuthRatioPct, authRequests,
				incidentEventRatioPct, mitigatedAsnRatioPct, uaMismatchRatioPct,
				datacenterRatioPct, avgRequestsPerSlot, thresholds, topOrigins,
				hourlyHistory, historyFromLiveEvents, List.of());
	}

	public String hexHash32() {
		return String.format("0x%08x", uaHash32);
	}

	public Optional<MitigationUaRule> activeBlockRule() {
		if (mitigationRules == null || mitigationRules.isEmpty()) {
			return Optional.empty();
		}
		Instant now = Instant.now();
		return mitigationRules.stream().filter(r -> r.isCurrentlyActive(now)).findFirst();
	}

	public boolean hasActiveBlockRule() {
		return activeBlockRule().isPresent();
	}

	public List<MitigationUaRule> getMitigationRules() {
		return mitigationRules != null ? mitigationRules : List.of();
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
