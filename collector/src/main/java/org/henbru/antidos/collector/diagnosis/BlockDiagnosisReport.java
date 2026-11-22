package org.henbru.antidos.collector.diagnosis;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientSubnetRollup;
import org.henbru.antidos.collector.model.IpEnrichmentResult;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.MitigationUaRule;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.henbru.antidos.collector.model.UserAgentProfile;

/**
 * Structured multi-pillar diagnosis result explaining why an IP, User-Agent, or URL
 * was blocked (or allowed/bypassed) within a queried time window.
 */
public record BlockDiagnosisReport(
		VerdictLevel verdictLevel,
		String verdictHeadline,
		String verdictSummary,
		Instant windowStart,
		Instant windowEnd,
		Instant referenceTime,
		String normalizedIp,
		String normalizedUrlPath,
		String userAgentQuery,
		Integer computedUaHash32,
		boolean assumeAuthenticated,
		boolean assumeReturningVisitor,
		NetworkContext networkContext,
		List<Finding> findings,
		List<String> recommendedSteps,
		List<String> transparencyNotes,
		List<DynamicCidrMatch> dynamicCidrMatches,
		List<DynamicUaMatch> dynamicUaMatches,
		List<MitigationAuditEntry> relatedAuditEntries,
		List<UserAgentProfile> matchedUaProfiles,
		List<ObservedEventMatch> blockedOrMarkedEvents,
		List<ObservedEventMatch> activeEvents,
		List<ClientSubnetRollup> matchedRollups,
		List<ValvePipelineEvaluation> valveEvaluations,
		boolean subnetCollateralDetected
) {
	private static final DateTimeFormatter TS_FMT =
			DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

	public enum VerdictLevel {
		LIKELY_BLOCKED,
		POSSIBLE_BLOCK,
		BYPASSED_OR_ALLOWED,
		NO_EVIDENCE,
		INVALID_INPUT
	}

	public record Finding(
			String severity,
			String category,
			String title,
			String detail,
			String serverId,
			String valveName,
			String actionUrl,
			String actionLabel
	) {
	}

	public record NetworkContext(
			String inputIp,
			String normalizedIp,
			int ipVersion,
			String canonicalSubnet,
			boolean privateOrLocal,
			String privateDescription,
			IpEnrichmentResult enrichment,
			String botName,
			String botCategory,
			List<String> intelLabels,
			List<NetworkAnnotation> annotations
	) {
	}

	public record DynamicCidrMatch(
			MitigationRule rule,
			boolean activeNow,
			boolean activeInWindow,
			List<String> enforcedOnValves,
			List<String> bypassedOnValves
	) {
		public String formattedCreatedAt() {
			return rule != null && rule.createdAt() != null ? TS_FMT.format(rule.createdAt()) : "-";
		}

		public String formattedExpiresAt() {
			return rule != null && rule.expiresAt() != null ? TS_FMT.format(rule.expiresAt()) : "-";
		}
	}

	public record DynamicUaMatch(
			MitigationUaRule rule,
			boolean exactHashMatch,
			boolean activeNow,
			boolean activeInWindow,
			boolean bypassedByContext,
			String bypassExplanation
	) {
		public String formattedExpiresAt() {
			return rule != null && rule.expiresAt() != null ? TS_FMT.format(rule.expiresAt()) : "-";
		}

		public String formattedCreatedAt() {
			return rule != null && rule.createdAt() != null ? TS_FMT.format(rule.createdAt()) : "-";
		}
	}

	public record ValvePipelineEvaluation(
			String serverId,
			String valveName,
			int pipelineOrder,
			String monitorMode,
			boolean simulationMode,
			boolean serverWideBlocking,
			boolean honeypot,
			boolean dynamicMitigationEnabled,
			String relevantAuthScope,
			String staticIpVerdict,
			String mitigationBypassVerdict,
			String urlMatchVerdict,
			String authScopeVerdict,
			String effectiveOutcome,
			String summaryNote
	) {
		public boolean isEnforcingBlockMode() {
			return !simulationMode && "BLOCKING".equalsIgnoreCase(monitorMode);
		}
	}

	public record ObservedEventMatch(
			ClientEvent event,
			boolean exactIpMatch,
			boolean subnetCollateralMatch,
			boolean sampleUriMatches,
			boolean sampleUaMatches
	) {
		public String formattedSlotTime() {
			return event != null && event.slotTime() != null ? TS_FMT.format(event.slotTime()) : "-";
		}
	}

	public String formattedWindowStart() {
		return windowStart != null ? TS_FMT.format(windowStart) : "-";
	}

	public String formattedWindowEnd() {
		return windowEnd != null ? TS_FMT.format(windowEnd) : "-";
	}

	public String formattedReferenceTime() {
		return referenceTime != null ? TS_FMT.format(referenceTime) : null;
	}

	public String formattedHexUaHash32() {
		return computedUaHash32 != null && computedUaHash32 != 0
				? String.format("0x%08x", computedUaHash32)
				: null;
	}

	public String verdictBadgeLabel() {
		return switch (verdictLevel) {
			case LIKELY_BLOCKED -> "LIKELY BLOCKED BY VALVE";
			case POSSIBLE_BLOCK -> "POSSIBLE / HISTORICAL MATCH";
			case BYPASSED_OR_ALLOWED -> "BYPASSED OR EXEMPTED";
			case NO_EVIDENCE -> "NO VALVE BLOCK EVIDENCE FOUND";
			case INVALID_INPUT -> "INVALID SEARCH INPUT";
		};
	}

	public String formatInstant(Instant instant) {
		return instant != null ? TS_FMT.format(instant) : "-";
	}

	public boolean hasDynamicEvidence() {
		return (dynamicCidrMatches != null && !dynamicCidrMatches.isEmpty())
				|| (dynamicUaMatches != null && !dynamicUaMatches.isEmpty())
				|| (relatedAuditEntries != null && !relatedAuditEntries.isEmpty())
				|| (matchedUaProfiles != null && !matchedUaProfiles.isEmpty());
	}

	public boolean hasEventEvidence() {
		return (blockedOrMarkedEvents != null && !blockedOrMarkedEvents.isEmpty())
				|| (activeEvents != null && !activeEvents.isEmpty())
				|| (matchedRollups != null && !matchedRollups.isEmpty());
	}
}
