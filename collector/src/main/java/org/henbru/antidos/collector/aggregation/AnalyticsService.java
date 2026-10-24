package org.henbru.antidos.collector.aggregation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import org.henbru.antidos.collector.model.AnalyticsDashboardDto;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.SubnetScatterPoint;
import org.henbru.antidos.collector.model.TimelinePoint;
import org.henbru.antidos.collector.model.TrafficCompositionPoint;
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

	@Autowired
	public AnalyticsService(
			SubnetRollupRepository subnetRollupRepository,
			RollupAggregationService rollupAggregationService
	) {
		this.subnetRollupRepository = subnetRollupRepository;
		this.rollupAggregationService = rollupAggregationService;
	}

	public AnalyticsDashboardDto getDashboardAnalytics(
			int hours,
			List<String> servers,
			List<String> valves
	) {
		int safeHours = hours > 0 ? hours : 24;
		Instant to = Instant.now();
		Instant from = to.minus(safeHours, ChronoUnit.HOURS);

		// 1. Timeline Points
		List<TimelinePoint> timeline = subnetRollupRepository.findTimeline(servers, valves, from, to);
		if (timeline.isEmpty() && safeHours <= 24) {
			// Trigger on-demand rollup catch-up if tables are fresh or pending
			rollupAggregationService.aggregateCatchUp(Math.min(safeHours, 24));
			timeline = subnetRollupRepository.findTimeline(servers, valves, from, to);
		}

		long totalRequests = 0;
		long totalActive = 0;
		long totalBlocked = 0;

		for (TimelinePoint pt : timeline) {
			totalRequests += pt.totalRequests();
			totalActive += pt.activeRequests();
			totalBlocked += pt.blockedRequests();
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
					row.subnetCount(),
					roundedPct
			));
		}

		// 3. Residential Proxy & Subnet Scatterplot Points (Top 150 clusters)
		List<SubnetRollupRepository.RawScatterCluster> rawClusters =
				subnetRollupRepository.findScatterClusters(servers, valves, from, to, 150);

		List<SubnetScatterPoint> scatterPoints = new ArrayList<>();
		for (SubnetRollupRepository.RawScatterCluster c : rawClusters) {
			int distinctClients = Math.max(1, c.distinctClients());
			double avgReqs = Math.round(((double) c.totalRequests() / distinctClients) * 10.0) / 10.0;
			boolean isResidential = (c.clientType() == ClientType.RESIDENTIAL || distinctClients >= 5) && avgReqs < 50.0;

			String classification;
			if (isResidential && c.blockedRequests() > 0) {
				classification = "HIGH_RISK_RESIDENTIAL";
			} else if (c.clientType() == ClientType.DATACENTER) {
				classification = "DATACENTER_CLUSTER";
			} else if (c.clientType() == ClientType.TOR_EXIT_NODE) {
				classification = "TOR_ANONYMIZER";
			} else if (c.clientType() == ClientType.AI_CRAWLER || c.clientType() == ClientType.SEARCH_ENGINE) {
				classification = "VERIFIED_BOT";
			} else if (distinctClients >= 10) {
				classification = "DISTRIBUTED_ACTIVE";
			} else {
				classification = "REGULAR_SUBNET";
			}

			scatterPoints.add(new SubnetScatterPoint(
					c.subnetGroup(),
					distinctClients,
					avgReqs,
					c.totalRequests(),
					c.blockedRequests(),
					isResidential,
					c.asn(),
					c.asOrg() != null ? c.asOrg() : "Unknown Provider",
					c.countryCode() != null ? c.countryCode() : "--",
					c.clientType(),
					classification
			));
		}

		double blockedRatio = totalRequests > 0
				? Math.round(((double) totalBlocked / totalRequests) * 1000.0) / 10.0
				: 0.0;

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
				blockedRatio
		);
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
			case PRIVATE_NETWORK -> "Private / Internal RFC 1918";
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
			case PRIVATE_NETWORK -> "🔒";
			case UNKNOWN -> "👤";
		};
	}
}
