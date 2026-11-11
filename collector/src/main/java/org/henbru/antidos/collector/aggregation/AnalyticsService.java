package org.henbru.antidos.collector.aggregation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.henbru.antidos.collector.advisor.AdvisorReport;
import org.henbru.antidos.collector.annotation.NetworkAnnotationService;
import org.henbru.antidos.collector.model.AnalyticsDashboardDto;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.henbru.antidos.collector.model.SubnetScatterPoint;
import org.henbru.antidos.collector.model.TimelinePoint;
import org.henbru.antidos.collector.model.TrafficCompositionPoint;
import org.henbru.antidos.collector.model.UserAgentAnalyticsDto;
import org.henbru.antidos.collector.model.UserAgentFamily;
import org.henbru.antidos.collector.model.UserAgentFamilySummary;
import org.henbru.antidos.collector.model.UserAgentItemSummary;
import org.henbru.antidos.collector.model.UserAgentOriginSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
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

	@Autowired
	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			@Autowired(required = false) NetworkAnnotationService networkAnnotationService,
			@Autowired(required = false) org.henbru.antidos.collector.advisor.AdvisorService advisorService,
			@Autowired(required = false) org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository,
			@Autowired(required = false) MonitoredValveRepository monitoredValveRepository
	) {
		this.subnetRollupRepository = subnetRollupRepository;
		this.rollupAggregationService = rollupAggregationService;
		this.networkAnnotationService = networkAnnotationService;
		this.advisorService = advisorService;
		this.clientEventRepository = clientEventRepository;
		this.monitoredValveRepository = monitoredValveRepository;
	}

	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService,
			NetworkAnnotationService networkAnnotationService,
			org.henbru.antidos.collector.advisor.AdvisorService advisorService,
			org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository
	) {
		this(subnetRollupRepository, rollupAggregationService, networkAnnotationService, advisorService, clientEventRepository, null);
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
		return getDashboardAnalytics(hours, null, null, servers, valves, "SUBNET", "ALL", "ALL");
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			int hours,
			List<String> servers,
			List<String> valves,
			String groupBy,
			String trafficFilter,
			String authFilter
	) {
		return getDashboardAnalytics(hours, null, null, servers, valves, groupBy, trafficFilter, authFilter);
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
		int safeHours = hours > 0 ? hours : 24;
		Instant to = toTime != null ? toTime : Instant.now();
		Instant from = fromTime != null ? fromTime : to.minus(safeHours, ChronoUnit.HOURS);
		String effectiveGroupBy = "ASN".equalsIgnoreCase(groupBy) ? "ASN" : "SUBNET";
		String effectiveTraffic = trafficFilter != null && !trafficFilter.isBlank() ? trafficFilter.trim().toUpperCase() : "ALL";
		String effectiveAuth = authFilter != null && !authFilter.isBlank() ? authFilter.trim().toUpperCase() : "ALL";

		// 1. Timeline Points
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

		// 2. Traffic Composition
		List<SubnetRollupRepository.RawCompositionRow> rawComp =
				subnetRollupRepository.findTrafficComposition(servers, valves, from, to);

		List<TrafficCompositionPoint> composition = new ArrayList<>();
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

		// 3. Residential Proxy & Subnet Scatterplot Points (Top 150 clusters)
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

		List<SubnetScatterPoint> scatterPoints = new ArrayList<>();
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

		double blockedRatio = totalRequests > 0
				? Math.round(((double) totalBlocked / totalRequests) * 1000.0) / 10.0
				: 0.0;
		double markedRatio = totalRequests > 0
				? Math.round(((double) totalMarked / totalRequests) * 1000.0) / 10.0
				: 0.0;

		AdvisorReport advisorReport = advisorService != null
				? advisorService.generateReport(safeHours, servers, valves) : null;

		UserAgentAnalyticsDto userAgents = getUserAgentAnalytics(safeHours, from, to, servers, valves);

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
				userAgents
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

		Map<UserAgentFamily, FamilyAggregator> familyMap = new EnumMap<>(UserAgentFamily.class);
		List<UserAgentItemSummary> items = new ArrayList<>();

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

			// Suspicion heuristics:
			boolean isSuspicious = false;
			List<String> reasons = new ArrayList<>();

			int totalIncidents = row.blockedCount() + row.markedCount();
			double incidentRatio = row.eventCount() > 0 ? (totalIncidents * 100.0 / row.eventCount()) : 0.0;
			int totalGeo = row.datacenterCount() + row.residentialCount();
			double dcRatio = totalGeo > 0 ? (row.datacenterCount() * 100.0 / totalGeo) : 0.0;

			if (family.isAutomated()) {
				isSuspicious = true;
				reasons.add(family == UserAgentFamily.BOT_CRAWLER ? "Crawler signature" : "Scraper / tool library signature");
			}
			if (incidentRatio >= 50.0 && totalIncidents >= 2) {
				isSuspicious = true;
				reasons.add(String.format(Locale.ROOT, "High incident rate (%.1f%% blocked/marked)", incidentRatio));
			}
			if (dcRatio >= 75.0 && row.datacenterCount() >= 2) {
				isSuspicious = true;
				reasons.add(String.format(Locale.ROOT, "Datacenter concentration (%.1f%%)", dcRatio));
			}
			if (family == UserAgentFamily.EMPTY) {
				isSuspicious = true;
				reasons.add("Empty User-Agent header");
			}

			// Top origins (subnets and ASNs)
			List<UserAgentOriginSummary> origins = clientEventRepository.findUserAgentTopOrigins(
					row.userAgent(), from, to, servers, valves, 4);

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
					String.join(" • ", reasons),
					origins
			));
		}

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
				items
		);
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
