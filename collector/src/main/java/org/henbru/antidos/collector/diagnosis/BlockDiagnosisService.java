package org.henbru.antidos.collector.diagnosis;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.henbru.antidos.collector.diagnosis.BlockDiagnosisReport.DynamicCidrMatch;
import org.henbru.antidos.collector.diagnosis.BlockDiagnosisReport.DynamicUaMatch;
import org.henbru.antidos.collector.diagnosis.BlockDiagnosisReport.Finding;
import org.henbru.antidos.collector.diagnosis.BlockDiagnosisReport.NetworkContext;
import org.henbru.antidos.collector.diagnosis.BlockDiagnosisReport.ObservedEventMatch;
import org.henbru.antidos.collector.diagnosis.BlockDiagnosisReport.ValvePipelineEvaluation;
import org.henbru.antidos.collector.diagnosis.BlockDiagnosisReport.VerdictLevel;
import org.henbru.antidos.collector.enrichment.IntelRegistry;
import org.henbru.antidos.collector.enrichment.IpEnrichmentService;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientSubnetRollup;
import org.henbru.antidos.collector.model.IpEnrichmentResult;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.MitigationUaRule;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.henbru.antidos.collector.model.UserAgentProfile;
import org.henbru.antidos.collector.storage.BotIpRangeRepository;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.MitigationUaRuleRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.henbru.antidos.collector.storage.NetworkAnnotationRepository;
import org.henbru.antidos.collector.storage.SubnetRollupRepository;
import org.henbru.antidos.collector.storage.UserAgentMemoryRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Performs read-only multi-pillar forensic diagnosis ("Block Diagnosis / Support Lookup")
 * across IP enrichment, static Valve pipeline rules, dynamic CIDR/UA mitigations,
 * User-Agent memory, observed slot events, and historical subnet rollups.
 */
@Service
public class BlockDiagnosisService {

	private static final int MAX_RULE_SCAN_LIMIT = 500;
	private static final int MAX_EVENT_SCAN_LIMIT = 200;
	private static final int MAX_ROLLUP_SCAN_LIMIT = 30;
	private static final int MAX_UA_PROFILE_LIMIT = 15;

	private final MonitoredValveRepository monitoredValveRepository;
	private final ClientEventRepository clientEventRepository;
	private final SubnetRollupRepository subnetRollupRepository;
	private final MitigationRuleRepository mitigationRuleRepository;
	private final MitigationUaRuleRepository mitigationUaRuleRepository;
	private final UserAgentMemoryRepository userAgentMemoryRepository;
	private final NetworkAnnotationRepository networkAnnotationRepository;
	private final BotIpRangeRepository botIpRangeRepository;
	private final IntelRegistry intelRegistry;
	private final IpEnrichmentService ipEnrichmentService;

	public BlockDiagnosisService(
			MonitoredValveRepository monitoredValveRepository,
			ClientEventRepository clientEventRepository,
			SubnetRollupRepository subnetRollupRepository,
			MitigationRuleRepository mitigationRuleRepository,
			MitigationUaRuleRepository mitigationUaRuleRepository,
			UserAgentMemoryRepository userAgentMemoryRepository,
			NetworkAnnotationRepository networkAnnotationRepository,
			BotIpRangeRepository botIpRangeRepository,
			IntelRegistry intelRegistry,
			@Autowired(required = false) IpEnrichmentService ipEnrichmentService) {
		this.monitoredValveRepository = monitoredValveRepository;
		this.clientEventRepository = clientEventRepository;
		this.subnetRollupRepository = subnetRollupRepository;
		this.mitigationRuleRepository = mitigationRuleRepository;
		this.mitigationUaRuleRepository = mitigationUaRuleRepository;
		this.userAgentMemoryRepository = userAgentMemoryRepository;
		this.networkAnnotationRepository = networkAnnotationRepository;
		this.botIpRangeRepository = botIpRangeRepository;
		this.intelRegistry = intelRegistry;
		this.ipEnrichmentService = ipEnrichmentService;
	}

	/**
	 * Executes the 6-stage forensic lookup for the supplied support query.
	 * Never mutates persistent state and safely tolerates optional criteria.
	 */
	public BlockDiagnosisReport diagnose(BlockDiagnosisRequest request) {
		Instant now = Instant.now();
		Instant windowEnd = request.windowEnd() != null ? request.windowEnd() : now;
		Instant windowStart = request.windowStart() != null
				? request.windowStart()
				: windowEnd.minus(24, ChronoUnit.HOURS);
		if (windowStart.isAfter(windowEnd)) {
			Instant swap = windowStart;
			windowStart = windowEnd;
			windowEnd = swap;
		}

		String rawIp = trimToNull(request.ipAddress());
		String rawUa = trimToNull(request.userAgent());
		String rawUrl = trimToNull(request.urlOrPath());

		List<String> transparencyNotes = new ArrayList<>();
		if (rawIp == null && rawUa == null && rawUrl == null) {
			return emptyInvalidReport(
					windowStart,
					windowEnd,
					request.referenceTime(),
					request.assumeAuthenticated(),
					request.assumeReturningVisitor(),
					"No search criteria provided",
					"Enter at least a client IP address, a User-Agent (substring or full header), or a URL/path to run a diagnosis.");
		}

		String strippedIp = normalizeHostPortInput(rawIp);
		IpNetworkInfo ipInfo = null;
		boolean isRangeInput = false;
		if (strippedIp != null) {
			ipInfo = parseStrictIp(strippedIp);
			if (ipInfo == null) {
				return emptyInvalidReport(
						windowStart,
						windowEnd,
						request.referenceTime(),
						request.assumeAuthenticated(),
						request.assumeReturningVisitor(),
						"Unparseable IP address or CIDR",
						"Could not parse '" + rawIp + "' as an IPv4/IPv6 address or CIDR range.");
			}
			isRangeInput = (ipInfo.version() == 4 && ipInfo.prefix() < 32)
					|| (ipInfo.version() == 6 && ipInfo.prefix() < 128);
			if (isRangeInput) {
				transparencyNotes.add("Input IP '" + strippedIp + "' is a CIDR subnet; per-IP regex rules (alwaysAllowedIPs / mitigationBypassIPs / alwaysForbiddenIPs) only match concrete host IPs unless a subnet prefix matches literally.");
			}
		}

		String normalizedUrlPath = normalizeUrlToPath(rawUrl, transparencyNotes);
		Integer computedUaHash32 = rawUa != null ? UserAgentMemoryRepository.computeUaHash32(rawUa) : null;

		List<MonitoredValve> activeValves = filterValves(
				monitoredValveRepository.findAllActive(),
				request.serverIds(),
				request.valveNames());

		if (activeValves.isEmpty()) {
			transparencyNotes.add("No active MonitoredValve metadata matched the selected server/valve filter.");
		}

		// Stage 1: Network & enrichment lookup
		NetworkContext networkContext = analyzeNetworkContext(strippedIp, ipInfo);

		// Stage 2 & 6: Static Valve IP/Bypass + URL/Auth pipeline evaluation
		List<ValveEvaluationInternal> internalValveEvals = evaluateValves(
				activeValves,
				strippedIp,
				ipInfo,
				networkContext != null && networkContext.privateOrLocal(),
				normalizedUrlPath,
				request.assumeAuthenticated());
		List<ValvePipelineEvaluation> valveEvaluations = internalValveEvals.stream()
				.map(ValveEvaluationInternal::evaluation)
				.toList();

		// Stage 3: Dynamic CIDR Mitigation Rules & Audit Log
		List<MitigationAuditEntry> auditWindow = mitigationRuleRepository.findAuditEntriesInWindow(
				windowStart, windowEnd, MAX_RULE_SCAN_LIMIT);

		List<DynamicCidrMatch> dynamicCidrMatches = evaluateDynamicCidrRules(
				ipInfo,
				internalValveEvals,
				now,
				windowStart,
				windowEnd);

		List<MitigationAuditEntry> relatedAuditEntries = filterRelatedAuditEntries(
				auditWindow, ipInfo, rawUa, computedUaHash32);

		// Stage 4: Dynamic User-Agent Rules & UA Memory
		List<DynamicUaMatch> dynamicUaMatches = evaluateDynamicUaRules(
				rawUa,
				computedUaHash32,
				internalValveEvals,
				ipInfo != null,
				request.assumeAuthenticated(),
				request.assumeReturningVisitor(),
				now,
				windowStart,
				windowEnd);

		List<UserAgentProfile> matchedUaProfiles = rawUa != null
				? lookupUaProfiles(rawUa)
				: List.of();

		// Stage 5: Observed Events & Historical Rollups
		List<ClientEvent> rawEvents = clientEventRepository.findEventsForDiagnosis(
				request.serverIds(),
				request.valveNames(),
				windowStart,
				windowEnd,
				strippedIp,
				rawUa,
				normalizedUrlPath,
				MAX_EVENT_SCAN_LIMIT);

		// Re-filter subnet queries carefully so concrete IP queries match both exact IP and overlapping /24 or /64 CIDRs,
		// and also fall back to client_subnet_rollups when detailed slot retention aged out.
		List<ObservedEventMatch> blockedOrMarkedEvents = new ArrayList<>();
		List<ObservedEventMatch> activeEvents = new ArrayList<>();
		boolean subnetCollateralDetected = classifyObservedEvents(
				rawEvents,
				strippedIp,
				ipInfo,
				rawUa,
				normalizedUrlPath,
				blockedOrMarkedEvents,
				activeEvents);

		List<ClientSubnetRollup> matchedRollups = (ipInfo != null && ipInfo.subnetGroup() != null)
				? subnetRollupRepository.findRollupsFiltered(
						request.serverIds(),
						request.valveNames(),
						windowStart,
						windowEnd,
						ipInfo.subnetGroup(),
						null,
						null,
						MAX_ROLLUP_SCAN_LIMIT,
						0)
				: List.of();

		if (ipInfo != null && !blockedOrMarkedEvents.isEmpty() && normalizedUrlPath != null) {
			boolean anyUrlMatch = blockedOrMarkedEvents.stream().anyMatch(ObservedEventMatch::sampleUriMatches);
			if (!anyUrlMatch) {
				transparencyNotes.add("Blocked/marked slot events for this IP/subnet carry a different sample URI than '"
						+ normalizedUrlPath
						+ "'. AntiDoSCounter retains only one representative sample request per slot window, so additional requests to your URL inside that blocked window still fail with HTTP 429.");
			}
		}
		if (blockedOrMarkedEvents.isEmpty() && activeEvents.isEmpty() && !matchedRollups.isEmpty()) {
			transparencyNotes.add("Detailed slot events for this time window have likely been purged by collector retention, while hourly subnet rollups remain available.");
		}
		if (rawUa != null && !dynamicUaMatches.isEmpty() && rawIp == null) {
			transparencyNotes.add("No IP address was provided, so IP-based dynamic mitigation bypasses (alwaysAllowedIPs, mitigationBypassPrivateIPs, mitigationBypassIPs) could not be evaluated.");
		}
		if (request.assumeReturningVisitor()) {
			transparencyNotes.add("Assuming a valid returning-visitor token (`__antidos_rv`) without User-Agent hash mismatch (`uaMismatch == false`). If the client tampered with its User-Agent or lacked a valid cookie, dynamic UA bypass would NOT apply.");
		}
		if (normalizedUrlPath != null) {
			transparencyNotes.add("Path matching evaluates `HttpServletRequest.getRequestURI()` with Java full-string regex (`Matcher.matches()`), matching `AntiDoSValve` behavior.");
		}

		// Build Findings, Verdict & Recommended Steps
		List<Finding> findings = buildFindings(
				strippedIp,
				ipInfo,
				rawUa,
				normalizedUrlPath,
				networkContext,
				internalValveEvals,
				dynamicCidrMatches,
				dynamicUaMatches,
				relatedAuditEntries,
				matchedUaProfiles,
				blockedOrMarkedEvents,
				activeEvents,
				matchedRollups,
				subnetCollateralDetected);

		VerdictResolution verdict = resolveVerdict(
				internalValveEvals,
				dynamicCidrMatches,
				dynamicUaMatches,
				relatedAuditEntries,
				matchedUaProfiles,
				blockedOrMarkedEvents,
				activeEvents,
				matchedRollups,
				normalizedUrlPath);

		List<String> recommendedSteps = buildRecommendedSteps(
				verdict.level(),
				strippedIp,
				rawUa,
				networkContext,
				dynamicCidrMatches,
				dynamicUaMatches,
				blockedOrMarkedEvents,
				matchedRollups,
				internalValveEvals);

		return new BlockDiagnosisReport(
				verdict.level(),
				verdict.headline(),
				verdict.summary(),
				windowStart,
				windowEnd,
				request.referenceTime(),
				strippedIp,
				normalizedUrlPath,
				rawUa,
				computedUaHash32,
				request.assumeAuthenticated(),
				request.assumeReturningVisitor(),
				networkContext,
				Collections.unmodifiableList(findings),
				Collections.unmodifiableList(recommendedSteps),
				Collections.unmodifiableList(transparencyNotes),
				Collections.unmodifiableList(dynamicCidrMatches),
				Collections.unmodifiableList(dynamicUaMatches),
				Collections.unmodifiableList(relatedAuditEntries),
				Collections.unmodifiableList(matchedUaProfiles),
				Collections.unmodifiableList(blockedOrMarkedEvents),
				Collections.unmodifiableList(activeEvents),
				Collections.unmodifiableList(matchedRollups),
				Collections.unmodifiableList(valveEvaluations),
				subnetCollateralDetected);
	}

	private BlockDiagnosisReport emptyInvalidReport(
			Instant windowStart,
			Instant windowEnd,
			Instant referenceTime,
			boolean assumeAuthenticated,
			boolean assumeReturningVisitor,
			String headline,
			String summary) {
		return new BlockDiagnosisReport(
				VerdictLevel.INVALID_INPUT,
				headline,
				summary,
				windowStart,
				windowEnd,
				referenceTime,
				null,
				null,
				null,
				null,
				assumeAuthenticated,
				assumeReturningVisitor,
				null,
				List.of(),
				List.of("Provide a client IPv4/IPv6 address (e.g. 198.51.100.42), a User-Agent string/fragment, or a request URL/path."),
				List.of(),
				List.of(),
				List.of(),
				List.of(),
				List.of(),
				List.of(),
				List.of(),
				List.of(),
				List.of(),
				false);
	}

	private NetworkContext analyzeNetworkContext(String ip, IpNetworkInfo ipInfo) {
		if (ip == null || ipInfo == null) {
			return null;
		}
		boolean privateOrLocal = IpNetworkUtil.isPrivateOrLocal(ip);
		String privateDesc = IpNetworkUtil.getPrivateNetworkDescription(ip);

		IpEnrichmentResult enrichment = ipEnrichmentService != null
				? ipEnrichmentService.enrich(ip)
				: IpEnrichmentResult.UNKNOWN;

		BotIpRangeRepository.BotMatch botMatch = botIpRangeRepository != null
				? botIpRangeRepository.findBotForIp(ip).orElse(null)
				: null;

		List<String> intelLabels = new ArrayList<>();
		if (intelRegistry != null) {
			IntelRegistry.IntelLookupResult intel = intelRegistry.lookup(ip);
			if (intel != null) {
				if (intel.primaryLabel() != null && !intel.primaryLabel().isBlank()) {
					intelLabels.add(intel.primaryLabel());
				}
				if (intel.tags() != null && !intel.tags().isBlank() && !intelLabels.contains(intel.tags())) {
					intelLabels.add(intel.tags());
				}
			}
		}

		List<NetworkAnnotation> annotations = new ArrayList<>();
		if (ipInfo.subnetGroup() != null && !ipInfo.subnetGroup().isBlank()) {
			networkAnnotationRepository.findBySubnet(ipInfo.subnetGroup()).ifPresent(annotations::add);
		}
		if (enrichment != null && enrichment.asn() != null) {
			networkAnnotationRepository.findByAsn(enrichment.asn()).ifPresent(annotations::add);
		}

		return new NetworkContext(
				ip,
				ip,
				ipInfo.version(),
				ipInfo.subnetGroup(),
				privateOrLocal,
				privateDesc,
				enrichment,
				botMatch != null ? botMatch.botName() : null,
				botMatch != null ? botMatch.category() : null,
				Collections.unmodifiableList(intelLabels),
				Collections.unmodifiableList(annotations));
	}

	private List<MonitoredValve> filterValves(
			List<MonitoredValve> valves, List<String> serverIds, List<String> valveNames) {
		if (valves == null || valves.isEmpty()) {
			return List.of();
		}
		List<MonitoredValve> filtered = new ArrayList<>(valves.size());
		for (MonitoredValve v : valves) {
			if (serverIds != null && !serverIds.isEmpty() && !serverIds.contains(v.serverId())) {
				continue;
			}
			if (valveNames != null && !valveNames.isEmpty() && !valveNames.contains(v.valveName())) {
				continue;
			}
			filtered.add(v);
		}
		return filtered;
	}

	private List<ValveEvaluationInternal> evaluateValves(
			List<MonitoredValve> valves,
			String normalizedIp,
			IpNetworkInfo ipInfo,
			boolean privateOrLocal,
			String normalizedUrlPath,
			boolean assumeAuthenticated) {
		List<ValveEvaluationInternal> result = new ArrayList<>(valves.size());
		boolean isConcreteHostIp = ipInfo != null
				&& ((ipInfo.version() == 4 && ipInfo.prefix() == 32)
				|| (ipInfo.version() == 6 && ipInfo.prefix() == 128));

		for (MonitoredValve v : valves) {
			boolean staticForbidden = false;
			boolean staticAlwaysAllowed = false;
			String staticIpVerdict;

			if (normalizedIp == null || ipInfo == null) {
				staticIpVerdict = "N/A (No IP)";
			} else if (isConcreteHostIp && matchesRegex(v.alwaysForbiddenIPs(), normalizedIp)) {
				staticForbidden = true;
				staticIpVerdict = "FORBIDDEN (alwaysForbiddenIPs)";
			} else if (v.alwaysAllowPrivateIPs() && privateOrLocal) {
				staticAlwaysAllowed = true;
				staticIpVerdict = "ALWAYS_ALLOWED (alwaysAllowPrivateIPs)";
			} else if (isConcreteHostIp && matchesRegex(v.alwaysAllowedIPs(), normalizedIp)) {
				staticAlwaysAllowed = true;
				staticIpVerdict = "ALWAYS_ALLOWED (alwaysAllowedIPs)";
			} else if (!isConcreteHostIp) {
				staticIpVerdict = "SKIPPED (CIDR Range Input)";
			} else {
				staticIpVerdict = "NEUTRAL";
			}

			boolean dynamicBypassedForIp = false;
			String mitigationBypassVerdict;
			if (!v.dynamicMitigationEnabled()) {
				mitigationBypassVerdict = "MITIGATION_DISABLED";
			} else if (staticAlwaysAllowed) {
				dynamicBypassedForIp = true;
				mitigationBypassVerdict = "BYPASSED (via static alwaysAllowed)";
			} else if (normalizedIp == null || ipInfo == null) {
				mitigationBypassVerdict = "UNKNOWN (No IP)";
			} else if (v.mitigationBypassPrivateIPs() && privateOrLocal) {
				dynamicBypassedForIp = true;
				mitigationBypassVerdict = "BYPASSED (mitigationBypassPrivateIPs)";
			} else if (isConcreteHostIp && matchesRegex(v.mitigationBypassIPs(), normalizedIp)) {
				dynamicBypassedForIp = true;
				mitigationBypassVerdict = "BYPASSED (mitigationBypassIPs)";
			} else if (!isConcreteHostIp) {
				mitigationBypassVerdict = "DEPENDS_ON_HOST_IP";
			} else {
				mitigationBypassVerdict = "ENFORCED";
			}

			boolean honeypot = v.isHoneypot() || v.allowedRequestsPerSlot() == 0;
			boolean urlExplicitlyRelevant = false;
			boolean urlExcluded = false;
			String urlMatchVerdict;

			if (normalizedUrlPath == null) {
				urlMatchVerdict = "N/A (No URL)";
			} else if (v.nonRelevantPaths() != null && !v.nonRelevantPaths().isBlank()
					&& matchesRegex(v.nonRelevantPaths(), normalizedUrlPath)) {
				urlExcluded = true;
				urlMatchVerdict = "EXCLUDED (nonRelevantPaths)";
			} else if (v.relevantPaths() != null && !v.relevantPaths().isBlank()) {
				if (matchesRegex(v.relevantPaths(), normalizedUrlPath)) {
					urlExplicitlyRelevant = true;
					urlMatchVerdict = honeypot ? "HONEYPOT_MATCH (relevantPaths)" : "MATCHES_RELEVANT";
				} else {
					urlMatchVerdict = v.serverWideBlocking()
							? "NO_PATH_MATCH (serverWideBlocking check only)"
							: "NOT_IN_RELEVANT_PATHS";
				}
			} else {
				urlMatchVerdict = "NO_PATH_FILTER";
			}

			boolean authOutOfScope = false;
			String scope = v.relevantAuthScope() != null && !v.relevantAuthScope().isBlank()
					? v.relevantAuthScope().trim().toUpperCase(Locale.ROOT)
					: "ALL";
			String authScopeVerdict;
			if ("AUTHENTICATED_ONLY".equals(scope)) {
				if (assumeAuthenticated) {
					authScopeVerdict = "IN_SCOPE (Authenticated)";
				} else {
					authOutOfScope = true;
					authScopeVerdict = "OUT_OF_SCOPE (Requires auth)";
				}
			} else if ("UNAUTHENTICATED_ONLY".equals(scope)) {
				if (assumeAuthenticated) {
					authOutOfScope = true;
					authScopeVerdict = "OUT_OF_SCOPE (Excluded for auth users)";
				} else {
					authScopeVerdict = "IN_SCOPE (Unauthenticated)";
				}
			} else {
				authScopeVerdict = "IN_SCOPE (ALL)";
			}

			String effectiveOutcome;
			String summaryNote;
			if (staticForbidden) {
				effectiveOutcome = v.simulationMode() ? "WOULD_BLOCK (SIMULATION)" : "BLOCKED_STATIC_FORBIDDEN";
				summaryNote = "Matches alwaysForbiddenIPs (overrides dynamic mitigation and bypass lists).";
			} else if (staticAlwaysAllowed) {
				effectiveOutcome = "EXEMPT_ALWAYS_ALLOWED";
				summaryNote = "Exempt from both sliding-window rate limits and dynamic mitigation.";
			} else if (urlExcluded) {
				effectiveOutcome = v.dynamicMitigationEnabled() && !dynamicBypassedForIp
						? "EXEMPT_FROM_RATE_LIMIT (Dynamic mitigation still runs earlier)"
						: "EXEMPT_NON_RELEVANT_PATH";
				summaryNote = "URL matches nonRelevantPaths; note dynamic CIDR/UA rules execute BEFORE nonRelevantPaths in AntiDoSValve.";
			} else if (authOutOfScope) {
				effectiveOutcome = v.dynamicMitigationEnabled() && !dynamicBypassedForIp
						? "OUT_OF_AUTH_SCOPE (Dynamic CIDR mitigation still runs earlier)"
						: "EXEMPT_AUTH_SCOPE";
				summaryNote = "Skipped by rate limiter due to relevantAuthScope=" + scope + ".";
			} else if (urlExplicitlyRelevant && honeypot) {
				effectiveOutcome = (!v.simulationMode() && "BLOCKING".equalsIgnoreCase(v.monitorMode()))
						? "HONEYPOT_INSTANT_BLOCK"
						: "HONEYPOT_DETECTED (" + (v.simulationMode() ? "Simulation" : v.monitorMode()) + ")";
				summaryNote = "Endpoint matches a Honeypot Valve (0 allowed requests per slot).";
			} else if (urlExplicitlyRelevant) {
				effectiveOutcome = (!v.simulationMode() && "BLOCKING".equalsIgnoreCase(v.monitorMode()))
						? "MONITORED_ENFORCING"
						: "MONITORED_NON_BLOCKING (" + (v.simulationMode() ? "Simulation" : v.monitorMode()) + ")";
				summaryNote = "Request falls inside active rate-limit scope ("
						+ v.allowedRequestsPerSlot() + " req / " + v.slotLength() + "s slot).";
			} else {
				effectiveOutcome = v.dynamicMitigationEnabled() && !dynamicBypassedForIp
						? "DYNAMIC_MITIGATION_ELIGIBLE"
						: "PASS_THROUGH_UNLESS_BLOCKED";
				summaryNote = v.serverWideBlocking()
						? "URL not counted, but serverWideBlocking=true still blocks already-blocked IPs."
						: "URL does not match relevantPaths on this valve.";
			}

			ValvePipelineEvaluation eval = new ValvePipelineEvaluation(
					v.serverId(),
					v.valveName(),
					v.pipelineOrder(),
					v.monitorMode(),
					v.simulationMode(),
					v.serverWideBlocking(),
					honeypot,
					v.dynamicMitigationEnabled(),
					scope,
					staticIpVerdict,
					mitigationBypassVerdict,
					urlMatchVerdict,
					authScopeVerdict,
					effectiveOutcome,
					summaryNote);
			result.add(new ValveEvaluationInternal(v, eval, staticForbidden, staticAlwaysAllowed,
					dynamicBypassedForIp, urlExplicitlyRelevant, urlExcluded, authOutOfScope, honeypot));
		}
		return result;
	}

	private List<DynamicCidrMatch> evaluateDynamicCidrRules(
			IpNetworkInfo ipInfo,
			List<ValveEvaluationInternal> valveEvals,
			Instant now,
			Instant windowStart,
			Instant windowEnd) {
		if (ipInfo == null) {
			return List.of();
		}

		Map<Long, MitigationRule> candidates = new LinkedHashMap<>();
		for (MitigationRule r : mitigationRuleRepository.findRulesOverlappingWindow(
				windowStart, windowEnd, MAX_RULE_SCAN_LIMIT)) {
			candidates.putIfAbsent(r.id(), r);
		}
		for (MitigationRule r : mitigationRuleRepository.findActiveRules(now)) {
			candidates.putIfAbsent(r.id(), r);
		}

		List<DynamicCidrMatch> matches = new ArrayList<>();
		for (MitigationRule rule : candidates.values()) {
			IpNetworkInfo ruleNet = parseStrictIp(rule.cidr());
			if (ruleNet == null || !ipIntervalsOverlap(ipInfo, ruleNet)) {
				continue;
			}
			boolean activeNow = rule.isActiveAt(now);
			boolean activeInWindow = overlapsTimeWindow(
					rule.createdAt(), rule.expiresAt(), rule.revokedAt(), windowStart, windowEnd);

			List<String> enforcedOn = new ArrayList<>();
			List<String> bypassedOn = new ArrayList<>();
			if (valveEvals.isEmpty()) {
				enforcedOn.add("Fleet (no active valve metadata synced)");
			} else {
				for (ValveEvaluationInternal ve : valveEvals) {
					if (!ve.valve().dynamicMitigationEnabled()
							|| !targetScopeMatches(rule.targetScope(), ve.valve().serverId())) {
						continue;
					}
					String label = ve.valve().serverId() + " / " + ve.valve().valveName();
					if (ve.dynamicBypassedForIp() || ve.staticAlwaysAllowed()) {
						bypassedOn.add(label + " (" + ve.evaluation().mitigationBypassVerdict() + ")");
					} else if (ve.valve().simulationMode()) {
						bypassedOn.add(label + " (Simulation Mode)");
					} else {
						enforcedOn.add(label);
					}
				}
			}

			matches.add(new DynamicCidrMatch(
					rule,
					activeNow,
					activeInWindow,
					Collections.unmodifiableList(enforcedOn),
					Collections.unmodifiableList(bypassedOn)));
		}
		return matches;
	}

	private List<DynamicUaMatch> evaluateDynamicUaRules(
			String rawUa,
			Integer computedUaHash32,
			List<ValveEvaluationInternal> valveEvals,
			boolean hasIpInput,
			boolean assumeAuthenticated,
			boolean assumeReturningVisitor,
			Instant now,
			Instant windowStart,
			Instant windowEnd) {
		if (rawUa == null || rawUa.isBlank()) {
			return List.of();
		}

		Map<Long, MitigationUaRule> candidates = new LinkedHashMap<>();
		for (MitigationUaRule r : mitigationUaRuleRepository.findRulesOverlappingWindow(
				windowStart, windowEnd, MAX_RULE_SCAN_LIMIT)) {
			candidates.putIfAbsent(r.id(), r);
		}
		for (MitigationUaRule r : mitigationUaRuleRepository.findActiveRules(now)) {
			candidates.putIfAbsent(r.id(), r);
		}

		String uaLower = rawUa.toLowerCase(Locale.ROOT);
		List<DynamicUaMatch> matches = new ArrayList<>();
		for (MitigationUaRule rule : candidates.values()) {
			boolean exactHashMatch = computedUaHash32 != null
					&& rule.uaHash32() == computedUaHash32
					&& rule.rawUserAgent() != null
					&& rule.rawUserAgent().equals(rawUa);
			boolean partialMatch = false;
			if (!exactHashMatch && rule.rawUserAgent() != null) {
				String ruleLower = rule.rawUserAgent().toLowerCase(Locale.ROOT);
				partialMatch = ruleLower.contains(uaLower) || uaLower.contains(ruleLower);
			}
			if (!exactHashMatch && !partialMatch) {
				continue;
			}

			boolean activeNow = rule.isActiveAt(now);
			boolean activeInWindow = overlapsTimeWindow(
					rule.createdAt(), rule.expiresAt(), rule.revokedAt(), windowStart, windowEnd);

			List<ValveEvaluationInternal> scopedMitigationValves = valveEvals.stream()
					.filter(ve -> ve.valve().dynamicMitigationEnabled()
							&& targetScopeMatches(rule.targetScope(), ve.valve().serverId()))
					.toList();

			boolean noMitigationEnabledInScope = !valveEvals.isEmpty() && scopedMitigationValves.isEmpty();
			boolean allMitigationValvesInSim = !scopedMitigationValves.isEmpty()
					&& scopedMitigationValves.stream().allMatch(ve -> ve.valve().simulationMode());
			boolean allValvesBypassIp = hasIpInput
					&& !scopedMitigationValves.isEmpty()
					&& scopedMitigationValves.stream().allMatch(
							ve -> ve.dynamicBypassedForIp() || ve.staticAlwaysAllowed());

			boolean bypassedByContext = assumeAuthenticated || assumeReturningVisitor || allValvesBypassIp
					|| noMitigationEnabledInScope || allMitigationValvesInSim;
			List<String> bypassReasons = new ArrayList<>();
			if (assumeAuthenticated) {
				bypassReasons.add("Authenticated user bypass");
			}
			if (assumeReturningVisitor) {
				bypassReasons.add("Returning visitor bypass (valid token, no UA mismatch)");
			}
			if (noMitigationEnabledInScope) {
				bypassReasons.add("Dynamic mitigation disabled on all in-scope valves");
			} else if (allMitigationValvesInSim) {
				bypassReasons.add("All in-scope mitigation valves run in Simulation Mode");
			}
			if (allValvesBypassIp) {
				bypassReasons.add("Client IP exempt on all in-scope mitigation valves");
			} else if (hasIpInput && scopedMitigationValves.stream().anyMatch(ValveEvaluationInternal::dynamicBypassedForIp)) {
				bypassReasons.add("Client IP bypassed on SOME valves (still enforced on others)");
			}

			matches.add(new DynamicUaMatch(
					rule,
					exactHashMatch,
					activeNow,
					activeInWindow,
					bypassedByContext,
					bypassReasons.isEmpty() ? "Enforced for anonymous/first-seen clients" : String.join("; ", bypassReasons)));
		}
		return matches;
	}

	private List<MitigationAuditEntry> filterRelatedAuditEntries(
			List<MitigationAuditEntry> auditWindow,
			IpNetworkInfo ipInfo,
			String rawUa,
			Integer computedUaHash32) {
		if (auditWindow == null || auditWindow.isEmpty()) {
			return List.of();
		}
		String hexHash = computedUaHash32 != null ? String.format("0x%08x", computedUaHash32) : null;
		String uaLower = rawUa != null ? rawUa.toLowerCase(Locale.ROOT) : null;

		List<MitigationAuditEntry> matched = new ArrayList<>();
		for (MitigationAuditEntry entry : auditWindow) {
			if (!entry.isUserAgentTarget() && ipInfo != null) {
				IpNetworkInfo targetNet = parseStrictIp(entry.cidr());
				if (targetNet != null && ipIntervalsOverlap(ipInfo, targetNet)) {
					matched.add(entry);
				}
			} else if (entry.isUserAgentTarget() && rawUa != null) {
				String target = entry.cidr() != null ? entry.cidr().toLowerCase(Locale.ROOT) : "";
				String details = entry.details() != null ? entry.details().toLowerCase(Locale.ROOT) : "";
				boolean matchHash = hexHash != null && (target.contains(hexHash) || details.contains(hexHash));
				boolean matchText = target.contains(uaLower) || details.contains(uaLower);
				if (matchHash || matchText) {
					matched.add(entry);
				}
			}
		}
		return matched;
	}

	private List<UserAgentProfile> lookupUaProfiles(String rawUa) {
		Map<Long, UserAgentProfile> deduped = new LinkedHashMap<>();
		Optional<UserAgentProfile> exact = userAgentMemoryRepository.findByRawUserAgent(rawUa);
		exact.ifPresent(p -> deduped.put(p.id(), p));
		for (UserAgentProfile p : userAgentMemoryRepository.searchProfilesBySubstring(rawUa, MAX_UA_PROFILE_LIMIT)) {
			deduped.putIfAbsent(p.id(), p);
		}
		return new ArrayList<>(deduped.values());
	}

	private boolean classifyObservedEvents(
			List<ClientEvent> rawEvents,
			String normalizedIp,
			IpNetworkInfo ipInfo,
			String rawUa,
			String normalizedUrlPath,
			List<ObservedEventMatch> blockedOrMarkedEvents,
			List<ObservedEventMatch> activeEvents) {
		if (rawEvents == null || rawEvents.isEmpty()) {
			return false;
		}
		boolean subnetCollateralDetected = false;
		String uaLower = rawUa != null ? rawUa.toLowerCase(Locale.ROOT) : null;
		String urlLower = normalizedUrlPath != null ? normalizedUrlPath.toLowerCase(Locale.ROOT) : null;

		for (ClientEvent ev : rawEvents) {
			boolean exactIp = false;
			boolean collateralSubnet = false;
			boolean isSyntheticUa = IpNetworkUtil.isSyntheticUaKey(ev.clientKey());
			if (ipInfo != null) {
				if (isSyntheticUa) {
					if (uaLower == null) {
						continue;
					}
				} else {
					IpNetworkInfo evIp = parseStrictIp(ev.clientKey());
					if (evIp == null || !ipIntervalsOverlap(ipInfo, evIp)) {
						continue;
					}
					if (evIp.prefix() < ipInfo.prefix()) {
						collateralSubnet = true;
					} else {
						exactIp = true;
					}
				}
			}

			boolean sampleUriMatches = urlLower != null
					&& ev.sampleUri() != null
					&& ev.sampleUri().toLowerCase(Locale.ROOT).contains(urlLower);
			boolean sampleUaMatches = uaLower != null
					&& ev.sampleUserAgent() != null
					&& ev.sampleUserAgent().toLowerCase(Locale.ROOT).contains(uaLower);

			ObservedEventMatch match = new ObservedEventMatch(
					ev, exactIp, collateralSubnet, sampleUriMatches, sampleUaMatches);
			if (ev.isBlocked() || ev.isMarked() || ev.isHoneypot()) {
				if (collateralSubnet) {
					subnetCollateralDetected = true;
				}
				blockedOrMarkedEvents.add(match);
			} else {
				activeEvents.add(match);
			}
		}
		return subnetCollateralDetected;
	}

	private List<Finding> buildFindings(
			String normalizedIp,
			IpNetworkInfo ipInfo,
			String rawUa,
			String normalizedUrlPath,
			NetworkContext networkContext,
			List<ValveEvaluationInternal> valveEvals,
			List<DynamicCidrMatch> dynamicCidrMatches,
			List<DynamicUaMatch> dynamicUaMatches,
			List<MitigationAuditEntry> relatedAuditEntries,
			List<UserAgentProfile> matchedUaProfiles,
			List<ObservedEventMatch> blockedOrMarkedEvents,
			List<ObservedEventMatch> activeEvents,
			List<ClientSubnetRollup> matchedRollups,
			boolean subnetCollateralDetected) {
		List<Finding> findings = new ArrayList<>();
		Integer computedUaHash32 = rawUa != null ? UserAgentMemoryRepository.computeUaHash32(rawUa) : null;

		// 1. Static Forbidden / Exempt Valves
		for (ValveEvaluationInternal ve : valveEvals) {
			MonitoredValve v = ve.valve();
			String serverUrl = "/server/" + encodeUrl(v.serverId());
			if (ve.staticForbidden()) {
				findings.add(new Finding(
						"BLOCKED",
						"Static IP List",
						"IP matches alwaysForbiddenIPs on " + v.serverId() + " (" + v.valveName() + ")",
						"Requests from " + normalizedIp + " are unconditionally blocked by static Valve regex before any bypass or rate limiter.",
						v.serverId(),
						v.valveName(),
						serverUrl,
						"View Valve Config"));
			} else if (ve.staticAlwaysAllowed()) {
				findings.add(new Finding(
						"BYPASSED",
						"Static Allowlist",
						"IP is permanently allowed on " + v.serverId() + " (" + v.valveName() + ")",
						"Covered by " + ve.evaluation().staticIpVerdict() + "; immune to rate limits and dynamic mitigation.",
						v.serverId(),
						v.valveName(),
						serverUrl,
						"View Valve Config"));
			}
		}

		// 2. Observed Slot Events (Blocked / Marked / Honeypot)
		if (!blockedOrMarkedEvents.isEmpty()) {
			long exactBlockedCount = blockedOrMarkedEvents.stream()
					.filter(m -> m.exactIpMatch() && (m.event().isBlocked() || m.event().isHoneypot()))
					.count();
			long markedCount = blockedOrMarkedEvents.stream()
					.filter(m -> m.event().isMarked())
					.count();
			long collateralCount = blockedOrMarkedEvents.stream()
					.filter(ObservedEventMatch::subnetCollateralMatch)
					.count();
			long syntheticUaBlockedCount = blockedOrMarkedEvents.stream()
					.filter(m -> IpNetworkUtil.isSyntheticUaKey(m.event().clientKey()) && (m.event().isBlocked() || m.event().isHoneypot()))
					.count();
			long uaMatchBlockedCount = blockedOrMarkedEvents.stream()
					.filter(m -> m.sampleUaMatches() && (m.event().isBlocked() || m.event().isHoneypot()))
					.count();

			String eventsUrl = "/events" + (normalizedIp != null ? "?clientQuery=" + encodeUrl(normalizedIp)
					: (computedUaHash32 != null ? "?clientQuery=" + encodeUrl("UA:" + computedUaHash32) : ""));
			if (exactBlockedCount > 0) {
				findings.add(new Finding(
						"BLOCKED",
						"Observed Valve Events",
						exactBlockedCount + " BLOCKED/HONEYPOT slot event(s) recorded in time window",
						"The Valve reported explicit blocked/honeypot events matching your query during the inspected window.",
						null,
						null,
						eventsUrl,
						"Open in Incident Explorer"));
			}
			if (syntheticUaBlockedCount > 0) {
				findings.add(new Finding(
						"BLOCKED",
						"Observed Dynamic UA Block Events",
						syntheticUaBlockedCount + " dynamic User-Agent block event(s) recorded in time window",
						"The Valve reported explicit HTTP 429 block events recorded under dynamic User-Agent rule counter(s).",
						null,
						null,
						eventsUrl,
						"Inspect UA Block Events"));
			}
			if (subnetCollateralDetected) {
				findings.add(new Finding(
						"BLOCKED",
						"Subnet Collateral Rate Limit",
						collateralCount + " blocked/marked event(s) in shared subnet "
								+ (ipInfo != null ? ipInfo.subnetGroup() : ""),
						"Traffic was rate-limited on a shared /24 or /64 subnet partition or neighbor key in the same subnet bucket (collateral block risk under NAT/carrier-grade/campus subnets).",
						null,
						null,
						eventsUrl,
						"Inspect Subnet Events"));
			}
			if (exactBlockedCount == 0 && syntheticUaBlockedCount == 0 && uaMatchBlockedCount > 0 && ipInfo == null) {
				findings.add(new Finding(
						"BLOCKED",
						"Observed User-Agent Block Events",
						uaMatchBlockedCount + " BLOCKED slot event(s) with matching User-Agent recorded in time window",
						"The Valve reported blocked slot events matching this User-Agent string during the inspected window.",
						null,
						null,
						eventsUrl,
						"Open in Incident Explorer"));
			}
			if (markedCount > 0 && exactBlockedCount == 0 && syntheticUaBlockedCount == 0 && !subnetCollateralDetected) {
				findings.add(new Finding(
						"WARNING",
						"Observed Marking Events",
						markedCount + " MARKED (Simulation/Marking mode) event(s) recorded",
						"Threshold was exceeded, but Valve acted in Marking/Simulation mode (traffic logged with HTTP 200 pass-through rather than HTTP 429).",
						null,
						null,
						eventsUrl,
						"Inspect Marked Events"));
			}
		}

		// 3. Dynamic CIDR Mitigation Rules
		for (DynamicCidrMatch match : dynamicCidrMatches) {
			MitigationRule r = match.rule();
			String mitUrl = match.activeNow() ? "/mitigation?tab=active" : "/mitigation?tab=history";
			if (!match.enforcedOnValves().isEmpty()) {
				findings.add(new Finding(
						match.activeInWindow() ? "BLOCKED" : "WARNING",
						"Dynamic CIDR Block",
						"CIDR rule " + r.cidr() + " (" + r.status() + ") "
								+ (match.activeInWindow() ? "overlapped query window" : "exists near window"),
						"Scope: " + r.targetScope() + " | Source: " + r.source()
								+ " | Reason: " + (r.reason() != null ? r.reason() : "-")
								+ " | Enforced on " + match.enforcedOnValves().size() + " valve(s).",
						null,
						null,
						mitUrl,
						match.activeNow() ? "View Active CIDR Rules" : "View Historical Rules"));
			} else if (!match.bypassedOnValves().isEmpty()) {
				findings.add(new Finding(
						"BYPASSED",
						"Dynamic CIDR Bypassed",
						"CIDR rule " + r.cidr() + " matched subnet, but was bypassed or disabled on in-scope valves",
						"Bypass details: " + String.join(", ", match.bypassedOnValves()),
						null,
						null,
						mitUrl,
						"Inspect CIDR Rule"));
			}
		}

		// 4. Dynamic User-Agent Mitigation Rules
		for (DynamicUaMatch match : dynamicUaMatches) {
			MitigationUaRule r = match.rule();
			String uaUrl = match.activeNow() ? "/mitigation?tab=useragents" : "/mitigation?tab=history";
			if (!match.bypassedByContext()) {
				findings.add(new Finding(
						match.exactHashMatch() && match.activeInWindow() ? "BLOCKED" : "WARNING",
						"Dynamic UA Block",
						(match.exactHashMatch() ? "Exact User-Agent hash " : "Partial User-Agent substring ")
								+ r.hexHash32() + " (" + r.status() + ")",
						"Browser family: " + r.browserFamily() + " | Source: " + r.source()
								+ " | " + match.bypassExplanation()
								+ " | Blocked hits: " + r.totalBlockedHits(),
						null,
						null,
						uaUrl,
						"View UA Rules"));
			} else {
				findings.add(new Finding(
						"BYPASSED",
						"Dynamic UA Block Bypassed",
						"User-Agent matched rule " + r.hexHash32() + ", but request context bypasses it",
						match.bypassExplanation(),
						null,
						null,
						uaUrl,
						"Inspect UA Rule"));
			}
		}

		// 5. UA Memory Verdict
		for (UserAgentProfile profile : matchedUaProfiles) {
			if (profile.isEffectiveSuspicious()) {
				findings.add(new Finding(
						"WARNING",
						"User-Agent Memory",
						"User-Agent rated SUSPICIOUS (" + profile.effectiveAutoVerdict() + ")",
						"Manual override: " + profile.effectiveOverride()
								+ " | 24h requests: " + profile.last24hRequests()
								+ " | Reason: " + (profile.autoVerdictReason() != null ? profile.autoVerdictReason() : "-"),
						null,
						null,
						"/mitigation?tab=useragents",
						"Open UA Memory"));
			} else if (profile.isEffectiveProtected()) {
				findings.add(new Finding(
						"INFO",
						"User-Agent Memory",
						"User-Agent rated PROTECTED (" + profile.effectiveAutoVerdict() + ")",
						"Protected from automated UA auto-blocking unless manually overridden.",
						null,
						null,
						"/mitigation?tab=useragents",
						"View UA Memory"));
			}
		}

		// 6. Historical Subnet Rollups fallback
		long totalRollupBlocked = matchedRollups.stream().mapToLong(ClientSubnetRollup::blockedRequests).sum();
		if (totalRollupBlocked > 0) {
			String profileUrl = "/profiles" + (ipInfo != null && ipInfo.subnetGroup() != null
					? "?q=" + encodeUrl(ipInfo.subnetGroup()) : "");
			findings.add(new Finding(
					blockedOrMarkedEvents.isEmpty() ? "WARNING" : "INFO",
					"Historical Subnet Rollup",
					matchedRollups.size() + " hourly subnet rollup bucket(s) show " + totalRollupBlocked + " blocked request(s)",
					"Hourly subnet aggregations confirm HTTP 429 blocks occurred for subnet "
							+ (ipInfo != null ? ipInfo.subnetGroup() : "") + " in this timeframe.",
					null,
					null,
					profileUrl,
					"Inspect Subnet Profile"));
		}

		// 7. Valve URL / Honeypot / Pipeline Exclusions
		if (normalizedUrlPath != null) {
			for (ValveEvaluationInternal ve : valveEvals) {
				MonitoredValve v = ve.valve();
				if (ve.honeypot() && ve.urlExplicitlyRelevant()) {
					findings.add(new Finding(
							ve.evaluation().isEnforcingBlockMode() ? "BLOCKED" : "WARNING",
							"Honeypot Valve Match",
							"URL '" + normalizedUrlPath + "' matches Honeypot Valve on " + v.serverId() + " (" + v.valveName() + ")",
							"Honeypot valves allow 0 requests per slot and block immediately.",
							v.serverId(),
							v.valveName(),
							"/server/" + encodeUrl(v.serverId()),
							"Inspect Honeypot Valve"));
				} else if (ve.urlExcluded()) {
					findings.add(new Finding(
							"INFO",
							"URL Excluded by nonRelevantPaths",
							"URL '" + normalizedUrlPath + "' is excluded from rate limiting on " + v.serverId() + " (" + v.valveName() + ")",
							"Only static alwaysForbiddenIPs or active dynamic mitigation rules can block this path on this valve.",
							v.serverId(),
							v.valveName(),
							"/server/" + encodeUrl(v.serverId()),
							"View Valve Rules"));
				}
			}
		}

		// 8. Enrichment / Bot / Audit Context
		if (networkContext != null) {
			if (networkContext.botName() != null) {
				findings.add(new Finding(
						"INFO",
						"Verified Crawler Feed",
						"IP belongs to verified crawler '" + networkContext.botName() + "' (" + networkContext.botCategory() + ")",
						"Crawler classification protects against automated dynamic CIDR blocking unless explicitly manually blocked.",
						null,
						null,
						"/crawlers",
						"View Crawler Feeds"));
			}
			if (!networkContext.intelLabels().isEmpty()) {
				findings.add(new Finding(
						"INFO",
						"Network Intelligence Match",
						"Threat/proxy intel match: " + String.join(", ", networkContext.intelLabels()),
						"IP belongs to a known cloud/hosting or curated threat-intel feed range.",
						null,
						null,
						"/notes",
						"View Network Notes"));
			}
			for (NetworkAnnotation note : networkContext.annotations()) {
				findings.add(new Finding(
						"INFO",
						"Operator Network Note",
						"Saved note (" + note.verdict() + ") for " + note.targetKey(),
						note.noteMarkdown() != null ? note.noteMarkdown() : "-",
						null,
						null,
						"/notes",
						"Open Notes"));
			}
		}

		if (!relatedAuditEntries.isEmpty()) {
			findings.add(new Finding(
					"INFO",
					"Mitigation Audit Log",
					relatedAuditEntries.size() + " mitigation lifecycle audit event(s) overlap this time window",
					"Includes rule creations, extensions, revocations, or TTL updates affecting this IP/subnet or User-Agent.",
					null,
					null,
					"/mitigation?tab=audit",
					"Open Mitigation Audit"));
		}

		return findings;
	}

	private VerdictResolution resolveVerdict(
			List<ValveEvaluationInternal> valveEvals,
			List<DynamicCidrMatch> dynamicCidrMatches,
			List<DynamicUaMatch> dynamicUaMatches,
			List<MitigationAuditEntry> relatedAuditEntries,
			List<UserAgentProfile> matchedUaProfiles,
			List<ObservedEventMatch> blockedOrMarkedEvents,
			List<ObservedEventMatch> activeEvents,
			List<ClientSubnetRollup> matchedRollups,
			String normalizedUrlPath) {

		boolean anyStaticForbiddenEnforced = valveEvals.stream()
				.anyMatch(ve -> ve.staticForbidden() && !ve.valve().simulationMode());
		boolean anyHoneypotEnforced = valveEvals.stream()
				.anyMatch(ve -> ve.honeypot()
						&& ve.urlExplicitlyRelevant()
						&& !ve.staticAlwaysAllowed()
						&& !ve.authOutOfScope()
						&& ve.evaluation().isEnforcingBlockMode());
		boolean anyConfirmedBlockedEvent = blockedOrMarkedEvents.stream()
				.anyMatch(m -> m.event().isBlocked() || m.event().isHoneypot());
		boolean anyCidrEnforcedInWindow = dynamicCidrMatches.stream()
				.anyMatch(m -> m.activeInWindow() && !m.enforcedOnValves().isEmpty());
		boolean anyUaExactEnforcedInWindow = dynamicUaMatches.stream()
				.anyMatch(m -> m.activeInWindow() && m.exactHashMatch() && !m.bypassedByContext());

		if (anyStaticForbiddenEnforced || anyHoneypotEnforced || anyConfirmedBlockedEvent
				|| anyCidrEnforcedInWindow || anyUaExactEnforcedInWindow) {
			List<String> reasons = new ArrayList<>();
			if (anyStaticForbiddenEnforced) {
				reasons.add("static alwaysForbiddenIPs rule");
			}
			if (anyHoneypotEnforced) {
				reasons.add("Honeypot URL match");
			}
			if (anyCidrEnforcedInWindow) {
				reasons.add("overlapping dynamic CIDR block");
			}
			if (anyUaExactEnforcedInWindow) {
				reasons.add("overlapping dynamic UA block (not bypassed)");
			}
			if (anyConfirmedBlockedEvent) {
				reasons.add("recorded BLOCKED/HONEYPOT slot event(s)");
			}
			return new VerdictResolution(
					VerdictLevel.LIKELY_BLOCKED,
					"Strong evidence that matching requests were blocked by Anti-DoS Valve",
					"Confirmed indicator(s): " + String.join(", ", reasons) + ".");
		}

		boolean anyMarkedEvent = blockedOrMarkedEvents.stream().anyMatch(m -> m.event().isMarked());
		boolean anySimulationForbidden = valveEvals.stream()
				.anyMatch(ve -> ve.staticForbidden() && ve.valve().simulationMode());
		boolean anyPartialUa = dynamicUaMatches.stream()
				.anyMatch(m -> m.activeInWindow() && !m.exactHashMatch() && !m.bypassedByContext());
		boolean anyHistoricalRollupBlocked = matchedRollups.stream().anyMatch(r -> r.blockedRequests() > 0);
		boolean anyAuditHit = !relatedAuditEntries.isEmpty();
		boolean anySuspiciousUaProfile = matchedUaProfiles.stream().anyMatch(UserAgentProfile::isEffectiveSuspicious);

		if (anyMarkedEvent || anySimulationForbidden || anyPartialUa
				|| anyHistoricalRollupBlocked || anyAuditHit || anySuspiciousUaProfile) {
			return new VerdictResolution(
					VerdictLevel.POSSIBLE_BLOCK,
					"Possible, marked, or historical block match found",
					"No active enforced HTTP 429 block with an exact full match was confirmed in current active telemetry, "
							+ "but marked/simulation hits, partial User-Agent matches, historical subnet rollups, or mitigation audit entries exist.");
		}

		boolean anyStaticAllowed = !valveEvals.isEmpty() && valveEvals.stream().allMatch(ValveEvaluationInternal::staticAlwaysAllowed);
		boolean anyBypassedRule = (!dynamicCidrMatches.isEmpty() && dynamicCidrMatches.stream().allMatch(m -> m.enforcedOnValves().isEmpty()))
				|| (!dynamicUaMatches.isEmpty() && dynamicUaMatches.stream().allMatch(DynamicUaMatch::bypassedByContext));
		boolean allUrlsExcluded = normalizedUrlPath != null && !valveEvals.isEmpty()
				&& valveEvals.stream().allMatch(ve -> ve.urlExcluded() || ve.authOutOfScope());

		if (anyStaticAllowed || anyBypassedRule || allUrlsExcluded) {
			return new VerdictResolution(
					VerdictLevel.BYPASSED_OR_ALLOWED,
					"Requests match a Valve allowlist, dynamic mitigation bypass, or path/auth exclusion",
					"Based on the queried configuration and context toggles, Anti-DoS Valve should allow this request (or bypass dynamic mitigation) without an HTTP 429 block.");
		}

		String extraContext = !activeEvents.isEmpty()
				? "Found " + activeEvents.size() + " active (non-blocked) event(s) below threshold in this timeframe."
				: "Neither static/dynamic rules nor observed blocked events matched inside this time window.";
		return new VerdictResolution(
				VerdictLevel.NO_EVIDENCE,
				"No Anti-DoS Valve block evidence found",
				extraContext + " If the user saw an HTTP error, check upstream WAF/reverse proxy logs or widen the lookup window.");
	}

	private List<String> buildRecommendedSteps(
			VerdictLevel level,
			String normalizedIp,
			String rawUa,
			NetworkContext networkContext,
			List<DynamicCidrMatch> dynamicCidrMatches,
			List<DynamicUaMatch> dynamicUaMatches,
			List<ObservedEventMatch> blockedOrMarkedEvents,
			List<ClientSubnetRollup> matchedRollups,
			List<ValveEvaluationInternal> valveEvals) {
		List<String> steps = new ArrayList<>();

		boolean hasActiveCidr = dynamicCidrMatches.stream().anyMatch(DynamicCidrMatch::activeNow);
		boolean hasActiveUa = dynamicUaMatches.stream().anyMatch(DynamicUaMatch::activeNow);

		if (hasActiveCidr) {
			steps.add("If this is legitimate campus/corporate traffic, revoke or shorten the active CIDR rule in Mitigation -> CIDR & ASN Defense, or add an exempt IP regex to mitigationBypassIPs / alwaysAllowedIPs.");
		}
		if (hasActiveUa) {
			steps.add("If a legitimate application or browser client was caught by User-Agent blocking, ask the user to log in first (authenticated bypass), ensure cookies are enabled, or mark the signature PROTECTED / revoke the rule in Mitigation -> User-Agent Defense.");
		}
		if (blockedOrMarkedEvents.stream().anyMatch(ObservedEventMatch::subnetCollateralMatch)
				|| (!matchedRollups.isEmpty() && blockedOrMarkedEvents.isEmpty())) {
			steps.add("Collateral subnet sharing detected: verify ipv4SubnetMask / ipv6SubnetMask on the affected Valve, or check Top Offenders / Subnet Profiles for noisy neighbor IPs inside the same subnet.");
		}
		if (networkContext != null && networkContext.privateOrLocal() && level == VerdictLevel.LIKELY_BLOCKED) {
			steps.add("Client IP is private/internal: verify RemoteIpValve / trusted proxy headers (X-Forwarded-For) so internal load-balancer IPs are not mistaken for end users.");
		}
		if (level == VerdictLevel.NO_EVIDENCE) {
			steps.add("Widen the tolerance/preset time window, verify the client IP matches Tomcat access logs (watch for IPv6 vs IPv4 fallback), or check reverse-proxy/WAF logs upstream of Tomcat.");
			boolean allInMonitoringOnly = !valveEvals.isEmpty()
					&& valveEvals.stream().noneMatch(ve -> ve.evaluation().isEnforcingBlockMode());
			if (allInMonitoringOnly) {
				steps.add("All evaluated Valves are currently in TRACKING_ONLY, MARKING, or Simulation mode and cannot emit HTTP 429 responses.");
			}
		}
		if (steps.isEmpty() && rawUa != null && normalizedIp != null) {
			steps.add("Compare the exact timestamp against Tomcat localhost_access_log filtering for " + normalizedIp + " with status 429 or Valve status code.");
		}
		return steps;
	}

	private static boolean overlapsTimeWindow(
			Instant createdAt,
			Instant expiresAt,
			Instant revokedAt,
			Instant windowStart,
			Instant windowEnd) {
		Instant effectiveStart = createdAt != null ? createdAt : Instant.EPOCH;
		Instant effectiveEnd = minNonNull(expiresAt, revokedAt);
		if (effectiveEnd == null) {
			effectiveEnd = Instant.parse("9999-12-31T23:59:59Z");
		}
		return !effectiveStart.isAfter(windowEnd) && !effectiveEnd.isBefore(windowStart);
	}

	private static Instant minNonNull(Instant a, Instant b) {
		if (a == null) {
			return b;
		}
		if (b == null) {
			return a;
		}
		return a.isBefore(b) ? a : b;
	}

	private static boolean targetScopeMatches(String targetScope, String serverId) {
		if (targetScope == null || targetScope.isBlank()
				|| "ALL".equalsIgnoreCase(targetScope)
				|| "*".equals(targetScope)
				|| "FLEET".equalsIgnoreCase(targetScope)) {
			return true;
		}
		if (serverId == null) {
			return false;
		}
		if (targetScope.equalsIgnoreCase(serverId)) {
			return true;
		}
		return targetScope.equalsIgnoreCase("SERVER:" + serverId);
	}

	private static boolean matchesRegex(String regexPattern, String value) {
		if (regexPattern == null || regexPattern.isBlank() || value == null) {
			return false;
		}
		try {
			return Pattern.compile(regexPattern).matcher(value).matches();
		} catch (PatternSyntaxException e) {
			return false;
		}
	}

	private static IpNetworkInfo parseStrictIp(String raw) {
		if (raw == null || raw.isBlank()) {
			return null;
		}
		IpNetworkInfo info = IpNetworkUtil.parse(raw);
		if (info.v4Start() == null && info.v6Start() == null) {
			return null;
		}
		return info;
	}

	private static boolean ipIntervalsOverlap(IpNetworkInfo a, IpNetworkInfo b) {
		if (a == null || b == null || a.version() != b.version()) {
			return false;
		}
		if (a.version() == 4 && a.v4Start() != null && a.v4End() != null
				&& b.v4Start() != null && b.v4End() != null) {
			return a.v4Start() <= b.v4End() && b.v4Start() <= a.v4End();
		}
		if (a.version() == 6 && a.v6Start() != null && a.v6End() != null
				&& b.v6Start() != null && b.v6End() != null) {
			return a.v6Start().compareTo(b.v6End()) <= 0 && b.v6Start().compareTo(a.v6End()) <= 0;
		}
		return false;
	}

	private static String normalizeHostPortInput(String rawIp) {
		if (rawIp == null) {
			return null;
		}
		String trimmed = rawIp.trim();
		if (trimmed.isEmpty()) {
			return null;
		}
		// [2001:db8::1]:12345 or [2001:db8::1]
		if (trimmed.startsWith("[")) {
			int closeBracket = trimmed.indexOf(']');
			if (closeBracket > 1) {
				trimmed = trimmed.substring(1, closeBracket);
			}
		} else {
			// Single IPv4:port like 198.51.100.42:8080
			long colonCount = trimmed.chars().filter(c -> c == ':').count();
			if (colonCount == 1 && trimmed.contains(".")) {
				int colonIdx = trimmed.indexOf(':');
				trimmed = trimmed.substring(0, colonIdx);
			}
		}
		// Strip IPv6 zone ID if present (e.g. fe80::1%eth0)
		int pctIdx = trimmed.indexOf('%');
		if (pctIdx > 0) {
			int slashIdx = trimmed.indexOf('/', pctIdx);
			trimmed = slashIdx > 0
					? trimmed.substring(0, pctIdx) + trimmed.substring(slashIdx)
					: trimmed.substring(0, pctIdx);
		}
		return trimmed;
	}

	private static String normalizeUrlToPath(String rawUrl, List<String> transparencyNotes) {
		if (rawUrl == null || rawUrl.isBlank()) {
			return null;
		}
		String s = rawUrl.trim();
		String extracted = s;
		String lower = s.toLowerCase(Locale.ROOT);
		if (lower.startsWith("http://") || lower.startsWith("https://")) {
			try {
				URI uri = URI.create(s);
				extracted = uri.getRawPath();
				if (extracted == null || extracted.isEmpty()) {
					extracted = "/";
				}
				if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) {
					transparencyNotes.add("Query string (`?" + uri.getRawQuery()
							+ "`) was stripped from URL path because `AntiDoSValve` evaluates `request.getRequestURI()` without query parameters.");
				}
				return extracted;
			} catch (IllegalArgumentException ignored) {
				int schemeEnd = s.indexOf("://") + 3;
				int pathStart = s.indexOf('/', schemeEnd);
				extracted = pathStart >= 0 ? s.substring(pathStart) : "/";
			}
		}

		int fragIdx = extracted.indexOf('#');
		if (fragIdx >= 0) {
			extracted = extracted.substring(0, fragIdx);
		}
		int qIdx = extracted.indexOf('?');
		if (qIdx >= 0) {
			String queryPart = extracted.substring(qIdx + 1);
			if (!queryPart.isEmpty()) {
				transparencyNotes.add("Query string (`?" + queryPart
						+ "`) was stripped from URL path because `AntiDoSValve` evaluates `request.getRequestURI()` without query parameters.");
			}
			extracted = extracted.substring(0, qIdx);
		}
		if (extracted.isEmpty()) {
			return "/";
		}
		if (!extracted.startsWith("/")) {
			extracted = "/" + extracted;
		}
		return extracted;
	}

	private static String trimToNull(String value) {
		if (value == null) {
			return null;
		}
		String t = value.trim();
		return t.isEmpty() ? null : t;
	}

	private static String encodeUrl(String value) {
		if (value == null) {
			return "";
		}
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

	private record ValveEvaluationInternal(
			MonitoredValve valve,
			ValvePipelineEvaluation evaluation,
			boolean staticForbidden,
			boolean staticAlwaysAllowed,
			boolean dynamicBypassedForIp,
			boolean urlExplicitlyRelevant,
			boolean urlExcluded,
			boolean authOutOfScope,
			boolean honeypot
	) {
	}

	private record VerdictResolution(
			VerdictLevel level,
			String headline,
			String summary
	) {
	}
}
