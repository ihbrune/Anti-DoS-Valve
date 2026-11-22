package org.henbru.antidos.collector.aggregation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.henbru.antidos.collector.advisor.AdvisorReport;
import org.henbru.antidos.collector.annotation.NetworkAnnotationService;
import org.henbru.antidos.collector.enrichment.BrowserVersionSyncService;
import org.henbru.antidos.collector.model.AnalyticsDashboardDto;
import org.henbru.antidos.collector.model.BrowserReferenceOverviewDto;
import org.henbru.antidos.collector.model.BrowserVersionLagAssessment;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.henbru.antidos.collector.model.SubnetScatterPoint;
import org.henbru.antidos.collector.model.TimelinePoint;
import org.henbru.antidos.collector.model.TrafficCompositionPoint;
import org.henbru.antidos.collector.model.EffectiveUaHeuristicSettings;
import org.henbru.antidos.collector.model.UserAgentAnalyticsDto;
import org.henbru.antidos.collector.model.UserAgentAutoVerdict;
import org.henbru.antidos.collector.model.UserAgentDrilldownDto;
import org.henbru.antidos.collector.model.UserAgentFamily;
import org.henbru.antidos.collector.model.UserAgentFamilySummary;
import org.henbru.antidos.collector.model.UserAgentIndicatorStats;
import org.henbru.antidos.collector.model.UserAgentItemSummary;
import org.henbru.antidos.collector.model.UserAgentManualOverride;
import org.henbru.antidos.collector.model.UserAgentOriginSummary;
import org.henbru.antidos.collector.model.UserAgentProfile;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.henbru.antidos.collector.storage.SubnetRollupRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service orchestrating analytical data extraction and formatting for telemetry charts,
 * including traffic timeline, bot-mix composition, and residential proxy cluster scatterplots.
 */
@Service
public class AnalyticsService {

	private final SubnetRollupRepository subnetRollupRepository;
	private final RollupAggregationService rollupAggregationService;
	private final NetworkAnnotationService networkAnnotationService;
	private final org.henbru.antidos.collector.advisor.AdvisorService advisorService;
	private final org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository;
	private final MonitoredValveRepository monitoredValveRepository;
	private final MitigationRuleRepository mitigationRuleRepository;
	private final BrowserVersionSyncService browserVersionSyncService;
	private final UserAgentMemoryService userAgentMemoryService;
	private final EndpointAnalyticsService endpointAnalyticsService;

	@Autowired
	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			@Autowired(required = false) NetworkAnnotationService networkAnnotationService,
			@Autowired(required = false) org.henbru.antidos.collector.advisor.AdvisorService advisorService,
			@Autowired(required = false) org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository,
			@Autowired(required = false) MonitoredValveRepository monitoredValveRepository,
			@Autowired(required = false) MitigationRuleRepository mitigationRuleRepository,
			@Autowired(required = false) BrowserVersionSyncService browserVersionSyncService,
			@Autowired(required = false) UserAgentMemoryService userAgentMemoryService,
			@Autowired(required = false) EndpointAnalyticsService endpointAnalyticsService
	) {
		this.subnetRollupRepository = subnetRollupRepository;
		this.rollupAggregationService = rollupAggregationService;
		this.networkAnnotationService = networkAnnotationService;
		this.advisorService = advisorService;
		this.clientEventRepository = clientEventRepository;
		this.monitoredValveRepository = monitoredValveRepository;
		this.mitigationRuleRepository = mitigationRuleRepository;
		this.browserVersionSyncService = browserVersionSyncService;
		this.userAgentMemoryService = userAgentMemoryService;
		this.endpointAnalyticsService = endpointAnalyticsService;
	}

	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			NetworkAnnotationService networkAnnotationService,
			org.henbru.antidos.collector.advisor.AdvisorService advisorService,
			org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository,
			MonitoredValveRepository monitoredValveRepository,
			MitigationRuleRepository mitigationRuleRepository,
			BrowserVersionSyncService browserVersionSyncService,
			UserAgentMemoryService userAgentMemoryService
	) {
		this(subnetRollupRepository, rollupAggregationService, networkAnnotationService, advisorService,
				clientEventRepository, monitoredValveRepository, mitigationRuleRepository, browserVersionSyncService, userAgentMemoryService, null);
	}

	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			NetworkAnnotationService networkAnnotationService,
			org.henbru.antidos.collector.advisor.AdvisorService advisorService,
			org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository,
			MonitoredValveRepository monitoredValveRepository,
			MitigationRuleRepository mitigationRuleRepository,
			BrowserVersionSyncService browserVersionSyncService
	) {
		this(subnetRollupRepository, rollupAggregationService, networkAnnotationService, advisorService,
				clientEventRepository, monitoredValveRepository, mitigationRuleRepository, browserVersionSyncService, null, null);
	}

	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			NetworkAnnotationService networkAnnotationService,
			org.henbru.antidos.collector.advisor.AdvisorService advisorService,
			org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository,
			MonitoredValveRepository monitoredValveRepository,
			MitigationRuleRepository mitigationRuleRepository
	) {
		this(subnetRollupRepository, rollupAggregationService, networkAnnotationService, advisorService, clientEventRepository, monitoredValveRepository, mitigationRuleRepository, null);
	}

	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			NetworkAnnotationService networkAnnotationService,
			org.henbru.antidos.collector.advisor.AdvisorService advisorService,
			org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository,
			MonitoredValveRepository monitoredValveRepository
	) {
		this(subnetRollupRepository, rollupAggregationService, networkAnnotationService, advisorService, clientEventRepository, monitoredValveRepository, null);
	}

	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			NetworkAnnotationService networkAnnotationService,
			org.henbru.antidos.collector.advisor.AdvisorService advisorService,
			org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository
	) {
		this(subnetRollupRepository, rollupAggregationService, networkAnnotationService, advisorService, clientEventRepository, null, null);
	}

	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService
	) {
		this(subnetRollupRepository, rollupAggregationService, null, null, null, null);
	}

	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			NetworkAnnotationService networkAnnotationService
	) {
		this(subnetRollupRepository, rollupAggregationService, networkAnnotationService, null, null, null);
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			int hours,
			List<String> servers,
			List<String> valves
	) {
		return getDashboardAnalytics("ALL", hours, null, null, servers, valves, "SUBNET", "ALL", "ALL");
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			String tab,
			int hours,
			List<String> servers,
			List<String> valves
	) {
		return getDashboardAnalytics(tab, hours, null, null, servers, valves, "SUBNET", "ALL", "ALL");
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			int hours,
			List<String> servers,
			List<String> valves,
			String groupBy,
			String trafficFilter,
			String authFilter
	) {
		return getDashboardAnalytics("ALL", hours, null, null, servers, valves, groupBy, trafficFilter, authFilter);
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			String tab,
			int hours,
			List<String> servers,
			List<String> valves,
			String groupBy,
			String trafficFilter,
			String authFilter
	) {
		return getDashboardAnalytics(tab, hours, null, null, servers, valves, groupBy, trafficFilter, authFilter);
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			int hours,
			Instant fromTime,
			Instant toTime,
			List<String> servers,
			List<String> valves,
			String groupBy,
			String trafficFilter,
			String authFilter
	) {
		return getDashboardAnalytics("ALL", hours, fromTime, toTime, servers, valves, groupBy, trafficFilter, authFilter);
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			String tab,
			int hours,
			Instant fromTime,
			Instant toTime,
			List<String> servers,
			List<String> valves,
			String groupBy,
			String trafficFilter,
			String authFilter
	) {
		return getDashboardAnalytics(tab, hours, fromTime, toTime, servers, valves, groupBy, trafficFilter, authFilter, false, true, "ALL");
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			String tab,
			int hours,
			Instant fromTime,
			Instant toTime,
			List<String> servers,
			List<String> valves,
			String groupBy,
			String trafficFilter,
			String authFilter,
			boolean excludeInternal,
			boolean excludeAutomated,
			String endpointStatus
	) {
		int safeHours = hours > 0 ? hours : 24;
		Instant to = toTime != null ? toTime : Instant.now();
		Instant from = fromTime != null ? fromTime : to.minus(safeHours, ChronoUnit.HOURS);
		String effectiveGroupBy = "ASN".equalsIgnoreCase(groupBy) ? "ASN" : "SUBNET";
		String effectiveTraffic = trafficFilter != null && !trafficFilter.isBlank() ? trafficFilter.trim().toUpperCase() : "ALL";
		String effectiveAuth = authFilter != null && !authFilter.isBlank() ? authFilter.trim().toUpperCase() : "ALL";

		boolean needAll = tab == null || tab.isBlank() || "all".equalsIgnoreCase(tab);
		boolean isCharts = needAll || "charts".equalsIgnoreCase(tab);
		boolean isScatter = needAll || "scatter".equalsIgnoreCase(tab);
		boolean isAdvisor = needAll || "advisor".equalsIgnoreCase(tab);
		boolean isUserAgents = needAll || "useragents".equalsIgnoreCase(tab);
		boolean isEndpoints = needAll || "endpoints".equalsIgnoreCase(tab);

		// 1. Timeline Points (always required for KPI cards and timeline chart)
		List<TimelinePoint> timeline = subnetRollupRepository.findTimeline(servers, valves, from, to);
		if (timeline.isEmpty() && safeHours <= 24 && fromTime == null && toTime == null) {
			// Trigger on-demand rollup catch-up if tables are fresh or pending
			rollupAggregationService.aggregateCatchUp(Math.min(safeHours, 24));
			timeline = subnetRollupRepository.findTimeline(servers, valves, from, to);
		}

		long totalRequests = 0;
		long totalActive = 0;
		long totalBlocked = 0;
		long totalMarked = 0;

		for (TimelinePoint pt : timeline) {
			totalRequests += pt.totalRequests();
			totalActive += pt.activeRequests();
			totalBlocked += pt.blockedRequests();
			totalMarked += pt.markedRequests();
		}

		// 2. Traffic Composition (only needed for charts tab or all)
		List<TrafficCompositionPoint> composition = new ArrayList<>();
		if (isCharts) {
			List<SubnetRollupRepository.RawCompositionRow> rawComp =
					subnetRollupRepository.findTrafficComposition(servers, valves, from, to);

			long compTotal = 0;
			for (SubnetRollupRepository.RawCompositionRow row : rawComp) {
				compTotal += row.totalRequests();
			}

			for (SubnetRollupRepository.RawCompositionRow row : rawComp) {
				double pct = compTotal > 0 ? (double) row.totalRequests() / compTotal * 100.0 : 0.0;
				double roundedPct = Math.round(pct * 10.0) / 10.0;
				composition.add(new TrafficCompositionPoint(
						row.clientType(),
						getClientTypeLabel(row.clientType()),
						getClientTypeIcon(row.clientType()),
						row.totalRequests(),
						row.blockedRequests(),
						row.markedRequests(),
						row.subnetCount(),
						roundedPct
				));
			}
		}

		// 3. Residential Proxy & Subnet Scatterplot Points (only needed for scatter tab or all)
		List<SubnetScatterPoint> scatterPoints = new ArrayList<>();
		if (isScatter) {
			List<SubnetRollupRepository.RawScatterCluster> rawClusters =
					("SUBNET".equals(effectiveGroupBy) && "ALL".equals(effectiveTraffic) && "ALL".equals(effectiveAuth))
							? subnetRollupRepository.findScatterClusters(servers, valves, from, to, 150)
							: subnetRollupRepository.findScatterClusters(servers, valves, from, to, effectiveGroupBy, effectiveTraffic, effectiveAuth, 150);

			Map<String, NetworkAnnotation> subnetNotes = (networkAnnotationService != null)
					? networkAnnotationService.getSubnetAnnotationMap()
					: Map.of();
			Map<Long, NetworkAnnotation> asnNotes = (networkAnnotationService != null)
					? networkAnnotationService.getAsnAnnotationMap()
					: Map.of();

			for (SubnetRollupRepository.RawScatterCluster c : rawClusters) {
				int distinctClients = Math.max(1, c.distinctClients());
				double avgReqs = Math.round(((double) c.totalRequests() / distinctClients) * 10.0) / 10.0;
				Double retRatio = c.returningRatio();
				boolean isHighReturningHumanNat = c.returningTrackedRequests() >= 20 && retRatio != null && retRatio >= 40.0 && c.blockedRequests() == 0;
				boolean isResidential = (c.clientType() == ClientType.RESIDENTIAL || distinctClients >= 5)
						&& avgReqs < 50.0
						&& !isHighReturningHumanNat;

				String classification;
				if (c.clientType() == ClientType.AI_CRAWLER || c.clientType() == ClientType.SEARCH_ENGINE) {
					classification = "VERIFIED_BOT";
				} else if (c.clientType() == ClientType.PRIVACY_RELAY) {
					classification = "PRIVACY_RELAY";
				} else if (c.clientType() == ClientType.TOR_EXIT_NODE) {
					classification = "TOR_ANONYMIZER";
				} else if (c.clientType() == ClientType.DATACENTER) {
					classification = "DATACENTER_CLUSTER";
				} else if (c.clientType() == ClientType.PRIVATE_NETWORK || c.clientType() == ClientType.INTERNAL_NETWORK) {
					classification = "REGULAR_SUBNET";
				} else if (isResidential && (distinctClients >= 5 || c.blockedRequests() > 0 || c.markedRequests() > 0)) {
					classification = "HIGH_RISK_RESIDENTIAL";
				} else if (distinctClients >= 10) {
					classification = "DISTRIBUTED_ACTIVE";
				} else {
					classification = "REGULAR_SUBNET";
				}

				// Forensic Notes lookup
				NetworkAnnotation subNote = (c.subnetGroup() != null) ? subnetNotes.get(c.subnetGroup().trim()) : null;
				NetworkAnnotation asNote = (c.asn() != null) ? asnNotes.get(c.asn()) : null;

				boolean hasNote = (subNote != null || asNote != null);
				String subnetNoteVerdict = (subNote != null && subNote.verdict() != null) ? subNote.verdict().displayName() : null;
				String subnetNoteIcon = (subNote != null && subNote.verdict() != null) ? subNote.verdict().icon() : null;
				String subnetNoteSnippet = (subNote != null) ? extractSnippet(subNote.noteMarkdown(), 70) : null;

				String asnNoteVerdict = (asNote != null && asNote.verdict() != null) ? asNote.verdict().displayName() : null;
				String asnNoteIcon = (asNote != null && asNote.verdict() != null) ? asNote.verdict().icon() : null;
				String asnNoteSnippet = (asNote != null) ? extractSnippet(asNote.noteMarkdown(), 70) : null;

				// Effective verdict (Subnet note takes precedence if present, else ASN note)
				NetworkAnnotation effectiveNote = (subNote != null) ? subNote : asNote;
				String noteVerdict = (effectiveNote != null && effectiveNote.verdict() != null) ? effectiveNote.verdict().name() : null;
				String noteVerdictIcon = (effectiveNote != null && effectiveNote.verdict() != null) ? effectiveNote.verdict().icon() : null;
				String noteVerdictDisplayName = (effectiveNote != null && effectiveNote.verdict() != null) ? effectiveNote.verdict().displayName() : null;
				String noteVerdictColor = (effectiveNote != null && effectiveNote.verdict() != null) ? effectiveNote.verdict().colorHex() : null;
				String noteSnippet = (subNote != null) ? subnetNoteSnippet : asnNoteSnippet;

				scatterPoints.add(new SubnetScatterPoint(
						c.subnetGroup(),
						distinctClients,
						c.distinctUserAgents(),
						avgReqs,
						c.totalRequests(),
						c.blockedRequests(),
						c.markedRequests(),
						isResidential,
						c.asn(),
						c.asOrg() != null ? c.asOrg() : "Unknown Provider",
						c.countryCode() != null ? c.countryCode() : "--",
						c.clientType(),
						classification,
						hasNote,
						noteVerdict,
						noteVerdictIcon,
						noteVerdictDisplayName,
						noteVerdictColor,
						noteSnippet,
						subnetNoteVerdict,
						subnetNoteIcon,
						subnetNoteSnippet,
						asnNoteVerdict,
						asnNoteIcon,
						asnNoteSnippet,
						retRatio,
						c.authenticatedRequests(),
						c.authenticatedTrackedRequests(),
						effectiveGroupBy
				));
			}
		}

		double blockedRatio = totalRequests > 0
				? Math.round(((double) totalBlocked / totalRequests) * 1000.0) / 10.0
				: 0.0;
		double markedRatio = totalRequests > 0
				? Math.round(((double) totalMarked / totalRequests) * 1000.0) / 10.0
				: 0.0;

		// 4. Configuration & False-Positive Advisor (only needed for advisor tab or all)
		AdvisorReport advisorReport = (isAdvisor && advisorService != null)
				? advisorService.generateReport(safeHours, servers, valves) : null;

		// 5. User-Agent Forensics (only needed for useragents tab or all)
		UserAgentAnalyticsDto userAgents = isUserAgents
				? getUserAgentAnalytics(safeHours, from, to, servers, valves) : null;

		// 6. Endpoint Forensics (only needed for endpoints tab or all)
		EndpointAnalyticsService.EndpointAnalyticsDashboard endpoints = (isEndpoints && endpointAnalyticsService != null)
				? endpointAnalyticsService.getEndpointAnalytics(safeHours, servers, valves, excludeInternal, excludeAutomated, endpointStatus, 50) : null;

		return new AnalyticsDashboardDto(
				from,
				to,
				safeHours,
				timeline,
				composition,
				scatterPoints,
				totalRequests,
				totalActive,
				totalBlocked,
				totalMarked,
				blockedRatio,
				markedRatio,
				advisorReport,
				effectiveGroupBy,
				effectiveTraffic,
				effectiveAuth,
				userAgents,
				endpoints
		);
	}

	public UserAgentAnalyticsDto getUserAgentAnalytics(
			int hours,
			Instant fromTime,
			Instant toTime,
			List<String> servers,
			List<String> valves
	) {
		if (clientEventRepository == null) {
			return UserAgentAnalyticsDto.empty(true, "ClientEventRepository is not available.");
		}
		int safeHours = hours > 0 ? hours : 24;
		Instant to = toTime != null ? toTime : Instant.now();
		Instant from = fromTime != null ? fromTime : to.minus(safeHours, ChronoUnit.HOURS);

		List<ClientEventRepository.RawUserAgentAggregation> rawList =
				clientEventRepository.findUserAgentAggregations(from, to, servers, valves, 50);

		int totalSampledEvents = 0;
		long totalSampledRequests = 0;
		int totalBlockedEvents = 0;
		int totalMarkedEvents = 0;
		int totalActiveEvents = 0;
		int totalAuthenticatedSamples = 0;

		Set<String> activeMitigatedCidrs = new HashSet<>();
		Map<Long, String> activeMitigatedAsns = new HashMap<>();

		if (mitigationRuleRepository != null) {
			try {
				Instant now = Instant.now();
				List<MitigationRule> activeRules = mitigationRuleRepository.findActiveRules(now);
				for (MitigationRule r : activeRules) {
					if (r.cidr() != null && !r.cidr().isBlank()) {
						activeMitigatedCidrs.add(r.cidr().trim());
					}
					if (r.asn() != null && r.asn() > 0) {
						String label = r.asnOrganization() != null && !r.asnOrganization().isBlank()
								? r.asnOrganization().trim() : ("AS" + r.asn());
						activeMitigatedAsns.putIfAbsent(r.asn(), label);
					}
				}

				List<MitigationRule> windowRules = mitigationRuleRepository.findRulesCreatedBetween(from, to);
				for (MitigationRule r : windowRules) {
					if (r.cidr() != null && !r.cidr().isBlank()) {
						activeMitigatedCidrs.add(r.cidr().trim());
					}
					if (r.asn() != null && r.asn() > 0) {
						String label = r.asnOrganization() != null && !r.asnOrganization().isBlank()
								? r.asnOrganization().trim() : ("AS" + r.asn());
						activeMitigatedAsns.putIfAbsent(r.asn(), label);
					}
				}
			} catch (Exception ignored) {
				// Non-fatal if mitigation repository is unavailable
			}
		}

		Map<UserAgentFamily, FamilyAggregator> familyMap = new EnumMap<>(UserAgentFamily.class);
		List<UserAgentItemSummary> items = new ArrayList<>();

		EffectiveUaHeuristicSettings heuristicSettings = userAgentMemoryService != null
				? userAgentMemoryService.getEffectiveSettings()
				: EffectiveUaHeuristicSettings.defaults();

		List<String> rawUaNames = rawList.stream()
				.map(ClientEventRepository.RawUserAgentAggregation::userAgent)
				.toList();
		Map<String, UserAgentProfile> storedProfiles = userAgentMemoryService != null
				? userAgentMemoryService.getProfilesMap(rawUaNames)
				: Map.of();

		for (ClientEventRepository.RawUserAgentAggregation row : rawList) {
			UserAgentFamily family = UserAgentClassifier.classify(row.userAgent());

			totalSampledRequests += row.totalRequests();
			totalSampledEvents += row.eventCount();
			totalBlockedEvents += row.blockedCount();
			totalMarkedEvents += row.markedCount();
			totalActiveEvents += row.activeCount();
			totalAuthenticatedSamples += row.authenticatedCount();

			FamilyAggregator famAgg = familyMap.computeIfAbsent(family, FamilyAggregator::new);
			famAgg.add(row.totalRequests(), row.eventCount(), row.blockedCount(), row.markedCount(), row.activeCount(), row.authenticatedCount());

			int totalIncidents = row.blockedCount() + row.markedCount();
			double incidentRatio = row.eventCount() > 0 ? (totalIncidents * 100.0 / row.eventCount()) : 0.0;
			int totalGeo = row.datacenterCount() + row.residentialCount();
			double dcRatio = totalGeo > 0 ? (row.datacenterCount() * 100.0 / totalGeo) : 0.0;
			double resRatio = totalGeo > 0 ? (row.residentialCount() * 100.0 / totalGeo) : 0.0;

			// Top origins (subnets and ASNs)
			List<UserAgentOriginSummary> origins = clientEventRepository.findUserAgentTopOrigins(
					row.userAgent(), from, to, servers, valves, 6);

			boolean mitigationMatch = false;
			String mitigationDetails = null;
			long mitigatedAsnRequests = 0L;
			if (!activeMitigatedCidrs.isEmpty() || !activeMitigatedAsns.isEmpty()) {
				for (UserAgentOriginSummary origin : origins) {
					if (origin.subnetGroup() != null && activeMitigatedCidrs.contains(origin.subnetGroup().trim())) {
						mitigationMatch = true;
						mitigationDetails = "Subnet " + origin.subnetGroup().trim() + " under active/recent mitigation";
						break;
					}
					if (origin.asn() != null && activeMitigatedAsns.containsKey(origin.asn())) {
						mitigationMatch = true;
						mitigationDetails = "ASN " + origin.asn() + " (" + activeMitigatedAsns.get(origin.asn()) + ") under active/recent mitigation";
						break;
					}
				}
				for (UserAgentOriginSummary origin : origins) {
					if (origin.asn() != null && activeMitigatedAsns.containsKey(origin.asn())) {
						mitigatedAsnRequests += origin.requests();
					}
				}
			}

			UserAgentProfile storedProfile = storedProfiles.get(row.userAgent().trim());
			UserAgentManualOverride manualOverride = storedProfile != null
					? storedProfile.effectiveOverride()
					: UserAgentManualOverride.AUTO;
			String operatorNote = storedProfile != null ? storedProfile.operatorNote() : null;
			Instant firstSeen = storedProfile != null ? storedProfile.firstSeenAt() : null;
			Instant lastSeen = storedProfile != null ? storedProfile.lastSeenAt() : null;

			boolean residentialZeroAuth = row.residentialCount() >= 10 && row.authenticatedCount() == 0
					&& (resRatio >= 50.0 || row.residentialCount() >= 25);

			UserAgentAutoVerdict autoVerdict;
			boolean isSuspicious = false;
			String suspicionReason;
			BrowserVersionLagAssessment versionAssessment = BrowserVersionLagAssessment.UNTRACKED;
			Integer parsedMajorVersion = null;
			Integer versionLagMajors = null;
			double internalRatioPct = row.totalRequests() > 0 ? Math.round((row.internalRequests() * 1000.0) / row.totalRequests()) / 10.0 : 0.0;
			double sampleAuthRatioPct = row.eventCount() > 0 ? Math.round((row.sampleAuthenticatedEvents() * 10000.0) / row.eventCount()) / 100.0 : 0.0;
			double slotAuthRatioPct = row.totalRequests() > 0 ? Math.round((row.slotAuthenticatedRequests() * 10000.0) / row.totalRequests()) / 100.0 : 0.0;
			double mitigatedAsnRatioPct = row.totalRequests() > 0 ? Math.round((mitigatedAsnRequests * 1000.0) / row.totalRequests()) / 10.0 : 0.0;
			double uaMismatchRatioPct = row.totalRequests() > 0 ? Math.round((row.uaMismatchRequests() * 1000.0) / row.totalRequests()) / 10.0 : 0.0;
			double avgReqsPerSlot = row.eventCount() > 0 ? Math.round((row.totalRequests() * 10.0) / row.eventCount()) / 10.0 : 0.0;

			if (userAgentMemoryService != null) {
				var eval = userAgentMemoryService.evaluateVerdict(new UserAgentMemoryService.EvaluationInput(
						row.userAgent(),
						family,
						row.totalRequests(),
						row.eventCount(),
						row.blockedCount(),
						row.markedCount(),
						row.distinctSubnets(),
						row.distinctAsns(),
						row.sampleAuthenticatedEvents(),
						row.slotAuthenticatedRequests(),
						row.internalRequests(),
						row.searchEngineRequests(),
						row.datacenterRequests(),
						row.residentialRequests(),
						mitigatedAsnRequests,
						row.uaMismatchRequests(),
						mitigationMatch,
						mitigationDetails
				), heuristicSettings);

				autoVerdict = eval.verdict();
				suspicionReason = eval.reason();
				versionAssessment = eval.versionAssessment();
				parsedMajorVersion = eval.parsedMajorVersion();
				versionLagMajors = eval.versionLagMajors();
				internalRatioPct = eval.internalRatioPct();
				sampleAuthRatioPct = eval.sampleAuthRatioPct();
				slotAuthRatioPct = eval.slotAuthRatioPct();
				mitigatedAsnRatioPct = eval.mitigatedAsnRatioPct();
				uaMismatchRatioPct = eval.uaMismatchRatioPct();
				avgReqsPerSlot = eval.avgRequestsPerSlot();
				if (eval.residentialZeroAuthAnomaly() && !autoVerdict.isImmune()) {
					residentialZeroAuth = true;
				}
				isSuspicious = manualOverride.isEffectiveSuspicious(autoVerdict);
				if (manualOverride == UserAgentManualOverride.MANUAL_BLOCK) {
					suspicionReason = "Manual override: Blocked by operator (" + eval.reason() + ")";
				} else if (manualOverride == UserAgentManualOverride.ALWAYS_ALLOW) {
					suspicionReason = "";
				} else if (manualOverride == UserAgentManualOverride.OBSERVE_ONLY) {
					suspicionReason = "Manual override: Observe only — auto-heuristic rated " + autoVerdict.displayName() + " (" + eval.reason() + ")";
				}
			} else {
				List<String> reasons = new ArrayList<>();
				if (family.isAutomated()) {
					isSuspicious = true;
					reasons.add(family == UserAgentFamily.BOT_CRAWLER ? "Crawler signature" : "Scraper / tool library signature");
				}
				if (family == UserAgentFamily.EMPTY) {
					isSuspicious = true;
					reasons.add("Empty User-Agent header");
				}
				if (incidentRatio >= 50.0 && totalIncidents >= 2) {
					isSuspicious = true;
					reasons.add(String.format(Locale.ROOT, "High incident rate (%.1f%% blocked/marked)", incidentRatio));
				}
				if (dcRatio >= 75.0 && row.datacenterCount() >= 2) {
					isSuspicious = true;
					reasons.add(String.format(Locale.ROOT, "Datacenter concentration (%.1f%%)", dcRatio));
				}
				if (residentialZeroAuth) {
					isSuspicious = true;
					reasons.add(String.format(Locale.ROOT, "Residential Zero-Auth anomaly (%d res samples, 0.0%% auth)", row.residentialCount()));
				}
				if (mitigationMatch) {
					isSuspicious = true;
					reasons.add(mitigationDetails != null ? mitigationDetails : "Origin in mitigated network");
				}
				if (browserVersionSyncService != null) {
					var vRes = browserVersionSyncService.assessUserAgent(family, row.userAgent());
					versionAssessment = vRes.assessment();
					parsedMajorVersion = vRes.parsedMajorVersion();
					versionLagMajors = vRes.versionLagMajors();

					if (versionAssessment == BrowserVersionLagAssessment.IMPLAUSIBLE_FUTURE) {
						isSuspicious = true;
						reasons.add(String.format(Locale.ROOT, "Implausible future version (%s v%d)", vRes.browserFamily(), parsedMajorVersion));
					} else if (versionAssessment == BrowserVersionLagAssessment.FORGED_BUILD_ANOMALY) {
						isSuspicious = true;
						reasons.add(String.format(Locale.ROOT, "Forged browser build number (%s v%d non-zero build/patch)", vRes.browserFamily(), parsedMajorVersion));
					} else if (versionAssessment == BrowserVersionLagAssessment.OBSOLETE_ANOMALY) {
						isSuspicious = true;
						reasons.add(String.format(Locale.ROOT, "Obsolete browser version (%s v%d, -%d lag)", vRes.browserFamily(), parsedMajorVersion, versionLagMajors));
					}
				}
				autoVerdict = isSuspicious ? UserAgentAutoVerdict.SUSPICIOUS_SIGNATURE
						: (row.authenticatedCount() > 0 ? UserAgentAutoVerdict.IMMUNE_AUTHENTICATED : UserAgentAutoVerdict.NEUTRAL);
				suspicionReason = String.join(" • ", reasons);
			}

			items.add(new UserAgentItemSummary(
					row.userAgent(),
					family,
					row.totalRequests(),
					row.eventCount(),
					row.blockedCount(),
					row.markedCount(),
					row.activeCount(),
					row.authenticatedCount(),
					Math.round(incidentRatio * 10.0) / 10.0,
					row.distinctSubnets(),
					row.distinctAsns(),
					row.datacenterCount(),
					row.residentialCount(),
					Math.round(dcRatio * 10.0) / 10.0,
					isSuspicious,
					isSuspicious || manualOverride.isManual() ? suspicionReason : "",
					origins,
					residentialZeroAuth,
					mitigationMatch,
					mitigationDetails,
					versionAssessment,
					parsedMajorVersion,
					versionLagMajors,
					storedProfile != null ? storedProfile.userAgentHash() : null,
					autoVerdict,
					manualOverride,
					operatorNote,
					firstSeen,
					lastSeen,
					internalRatioPct,
					sampleAuthRatioPct,
					slotAuthRatioPct,
					mitigatedAsnRatioPct,
					uaMismatchRatioPct,
					avgReqsPerSlot
			));
		}

		// Calculate indicator stats
		int suspiciousCount = 0;
		int standardCount = 0;
		int legitimateCount = 0;
		int residentialZeroAuthCount = 0;
		int mitigationMatchCount = 0;
		int highIncidentCount = 0;
		int datacenterCount = 0;
		int automatedCount = 0;
		int authenticatedCount = 0;
		int internalImmuneCount = 0;
		int searchEngineImmuneCount = 0;
		int manualOverrideCount = 0;

		for (UserAgentItemSummary item : items) {
			if (item.hasManualOverride()) manualOverrideCount++;
			if (item.safeAutoVerdict() == UserAgentAutoVerdict.IMMUNE_INTERNAL) internalImmuneCount++;
			if (item.safeAutoVerdict() == UserAgentAutoVerdict.IMMUNE_SEARCH_ENGINE) searchEngineImmuneCount++;

			if (item.isSuspicious()) {
				suspiciousCount++;
			} else if (item.hasAuthenticatedTraffic() || item.isImmune() || item.safeManualOverride() == UserAgentManualOverride.ALWAYS_ALLOW) {
				legitimateCount++;
			} else {
				standardCount++;
			}

			if (item.hasResidentialZeroAuthAnomaly()) residentialZeroAuthCount++;
			if (item.hasMitigationMatch()) mitigationMatchCount++;
			if (item.hasHighIncidentRate()) highIncidentCount++;
			if (item.hasDatacenterConcentration()) datacenterCount++;
			if (item.hasAutomatedSignature()) automatedCount++;
			if (item.hasAuthenticatedTraffic()) authenticatedCount++;
		}

		UserAgentIndicatorStats indicatorStats = new UserAgentIndicatorStats(
				items.size(),
				suspiciousCount,
				standardCount,
				legitimateCount,
				residentialZeroAuthCount,
				mitigationMatchCount,
				highIncidentCount,
				datacenterCount,
				automatedCount,
				authenticatedCount,
				internalImmuneCount,
				searchEngineImmuneCount,
				manualOverrideCount
		);

		// Family summaries
		List<UserAgentFamilySummary> families = new ArrayList<>();
		final long finalTotalRequests = totalSampledRequests;
		for (Map.Entry<UserAgentFamily, FamilyAggregator> entry : familyMap.entrySet()) {
			FamilyAggregator a = entry.getValue();
			double share = finalTotalRequests > 0 ? (a.requests * 100.0 / finalTotalRequests) : 0.0;
			int incidents = a.blocked + a.marked;
			double ratio = a.events > 0 ? (incidents * 100.0 / a.events) : 0.0;
			families.add(new UserAgentFamilySummary(
					entry.getKey(),
					a.requests,
					a.events,
					a.blocked,
					a.marked,
					a.active,
					a.auth,
					Math.round(ratio * 10.0) / 10.0,
					Math.round(share * 10.0) / 10.0
			));
		}
		families.sort(Comparator.comparingLong(UserAgentFamilySummary::totalRequests).reversed());

		// Sampling confidence calculation
		boolean hasLowConfidence = false;
		String confidenceMessage = null;

		boolean anyValveSamplingActive = monitoredValveRepository != null
				&& monitoredValveRepository.findAllActive().stream().anyMatch(v -> v.activeSampleThreshold() > 0);

		if (!anyValveSamplingActive && (totalBlockedEvents > 0 || totalMarkedEvents > 0)) {
			hasLowConfidence = true;
			confidenceMessage = "Limited Visibility (Incidents Only): Active sampling is disabled (activeSampleThreshold=\"0\") on your valves. Captured User-Agents exclusively reflect rate-limit blocking or marking incidents, causing an innate bias towards hostile clients. Configure activeSampleThreshold=\"50\" to establish a reliable baseline of legitimate user traffic.";
		} else if (totalSampledEvents < 20) {
			hasLowConfidence = true;
			confidenceMessage = "Low Sample Volume: Only " + totalSampledEvents + " request sample(s) recorded in this time window. Statistical significance is limited; consider expanding the timeframe (e.g. 24h) or adjusting activeSampleThreshold.";
		}

		return new UserAgentAnalyticsDto(
				totalSampledRequests,
				totalSampledEvents,
				items.size(),
				families.size(),
				totalBlockedEvents,
				totalMarkedEvents,
				totalActiveEvents,
				totalAuthenticatedSamples,
				hasLowConfidence,
				confidenceMessage,
				families,
				items,
				indicatorStats,
				browserVersionSyncService != null ? browserVersionSyncService.getOverview() : BrowserReferenceOverviewDto.empty(),
				heuristicSettings
		);
	}

	public UserAgentDrilldownDto getUserAgentDrilldown(String userAgent, int hours) {
		if (userAgentMemoryService != null) {
			return userAgentMemoryService.getUserAgentDrilldown(userAgent, hours);
		}
		return null;
	}

	private static class FamilyAggregator {
		final UserAgentFamily family;
		long requests = 0;
		int events = 0;
		int blocked = 0;
		int marked = 0;
		int active = 0;
		int auth = 0;

		FamilyAggregator(UserAgentFamily family) {
			this.family = family;
		}

		void add(long r, int e, int b, int m, int a, int au) {
			this.requests += r;
			this.events += e;
			this.blocked += b;
			this.marked += m;
			this.active += a;
			this.auth += au;
		}
	}

	private String getClientTypeLabel(ClientType type) {
		if (type == null) return "Unclassified Traffic";
		return switch (type) {
			case RESIDENTIAL -> "Residential ISP Connections";
			case DATACENTER -> "Datacenter / Cloud Servers";
			case SEARCH_ENGINE -> "Search Engines (Google, Bing)";
			case AI_CRAWLER -> "AI Crawlers & Scrapers";
			case MOBILE -> "Mobile Cellular Networks";
			case TOR_EXIT_NODE -> "Tor Anonymizer Exit Nodes";
			case PRIVACY_RELAY -> "Privacy Relays (iCloud Private Relay)";
			case PRIVATE_NETWORK -> "Private / Internal RFC 1918";
			case INTERNAL_NETWORK -> "Internal / Campus Network";
			case UNKNOWN -> "Unclassified / Standard Clients";
		};
	}

	private String getClientTypeIcon(ClientType type) {
		if (type == null) return "❓";
		return switch (type) {
			case RESIDENTIAL -> "🏠";
			case DATACENTER -> "🏢";
			case SEARCH_ENGINE -> "🔍";
			case AI_CRAWLER -> "🤖";
			case MOBILE -> "📱";
			case TOR_EXIT_NODE -> "🧅";
			case PRIVACY_RELAY -> "🛡️";
			case PRIVATE_NETWORK -> "🔒";
			case INTERNAL_NETWORK -> "🏛️";
			case UNKNOWN -> "👤";
		};
	}

	private String extractSnippet(String markdown, int maxLen) {
		if (markdown == null || markdown.isBlank()) {
			return "";
		}
		String firstLine = markdown.lines()
				.map(line -> line != null ? line.trim() : "")
				.filter(line -> !line.isEmpty())
				.findFirst()
				.orElse("");
		firstLine = firstLine.replaceAll("^[#\\*\\->\\s]+", "").replaceAll("[\\*`_]", "").trim();
		if (firstLine.length() > maxLen) {
			return firstLine.substring(0, maxLen - 1).trim() + "…";
		}
		return firstLine;
	}

	public org.henbru.antidos.collector.model.AsnDrilldownDto getAsnDrilldown(long asn, int hours) {
		int safeHours = hours > 0 ? Math.min(hours, 720) : 24;
		Instant to = Instant.now();
		Instant from = to.minus(safeHours, ChronoUnit.HOURS);

		List<org.henbru.antidos.collector.model.AsnHourlyPoint> points = subnetRollupRepository.findAsnHourlyPoints(asn, from, to);
		List<org.henbru.antidos.collector.model.AsnSubnetSummary> topSubnets = subnetRollupRepository.findAsnTopSubnets(asn, from, to, 15);
		SubnetRollupRepository.AsnMeta meta = subnetRollupRepository.findAsnMeta(asn);

		long totalRequests = 0;
		long totalBlocked = 0;
		long totalMarked = 0;
		long totalReturning = 0;
		long totalAuthenticated = 0;
		long totalClients = 0;
		java.util.Set<String> allSubnets = new java.util.HashSet<>();

		for (org.henbru.antidos.collector.model.AsnHourlyPoint pt : points) {
			totalRequests += pt.totalRequests();
			totalBlocked += pt.blockedRequests();
			totalMarked += pt.markedRequests();
			totalReturning += pt.returningRequests();
			totalAuthenticated += pt.authenticatedRequests();
			totalClients += pt.distinctClients();
		}

		for (org.henbru.antidos.collector.model.AsnSubnetSummary sub : topSubnets) {
			if (sub.subnetGroup() != null) {
				allSubnets.add(sub.subnetGroup());
			}
		}

		double overallReturningPct = totalRequests > 0 ? (totalReturning * 100.0 / totalRequests) : 0.0;

		int distinctUas = 0;
		List<org.henbru.antidos.collector.model.AsnUserAgentSummary> topUserAgents = List.of();
		if (clientEventRepository != null) {
			distinctUas = clientEventRepository.countAsnDistinctUserAgents(asn, from, to);
			topUserAgents = clientEventRepository.findAsnTopUserAgents(asn, from, to, 10, totalRequests);
		}

		return new org.henbru.antidos.collector.model.AsnDrilldownDto(
				asn,
				meta.asOrg() != null ? meta.asOrg() : ("AS" + asn),
				meta.countryCode(),
				meta.clientType(),
				safeHours,
				from,
				to,
				totalRequests,
				totalBlocked,
				totalMarked,
				totalReturning,
				Math.round(overallReturningPct * 10.0) / 10.0,
				totalAuthenticated,
				allSubnets.size(),
				totalClients,
				distinctUas,
				points,
				topSubnets,
				topUserAgents
		);
	}
}
