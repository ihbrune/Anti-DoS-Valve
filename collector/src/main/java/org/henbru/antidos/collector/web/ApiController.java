package org.henbru.antidos.collector.web;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.FleetSummary;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST API providing programmatic access to fleet telemetry and dynamic IP reputation lists.
 */
@RestController
@RequestMapping("/api/v1")
@SuppressWarnings("null")
public class ApiController {

	private final HeartbeatRepository heartbeatRepository;
	private final SlotSnapshotRepository slotSnapshotRepository;
	private final ClientEventRepository clientEventRepository;
	private final PollEventLogRepository pollEventLogRepository;
	private final org.henbru.antidos.collector.storage.SubnetRollupRepository subnetRollupRepository;
	private final org.henbru.antidos.collector.aggregation.RollupAggregationService rollupAggregationService;
	private final org.henbru.antidos.collector.aggregation.AnalyticsService analyticsService;
	private final org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository;
	private final org.henbru.antidos.collector.aggregation.SubnetProfileService subnetProfileService;

	@org.springframework.beans.factory.annotation.Autowired
	public ApiController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.storage.SubnetRollupRepository subnetRollupRepository,
			org.henbru.antidos.collector.aggregation.RollupAggregationService rollupAggregationService,
			org.henbru.antidos.collector.aggregation.AnalyticsService analyticsService,
			org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository,
			@org.springframework.beans.factory.annotation.Autowired(required = false) org.henbru.antidos.collector.aggregation.SubnetProfileService subnetProfileService) {
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.pollEventLogRepository = pollEventLogRepository;
		this.subnetRollupRepository = subnetRollupRepository;
		this.rollupAggregationService = rollupAggregationService;
		this.analyticsService = analyticsService;
		this.monitoredValveRepository = monitoredValveRepository;
		this.subnetProfileService = subnetProfileService;
	}

	public ApiController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.storage.SubnetRollupRepository subnetRollupRepository,
			org.henbru.antidos.collector.aggregation.RollupAggregationService rollupAggregationService,
			org.henbru.antidos.collector.aggregation.AnalyticsService analyticsService) {
		this(heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				subnetRollupRepository, rollupAggregationService, analyticsService, null, null);
	}

	@GetMapping("/fleet")
	public Map<String, Object> fleetOverview() {
		List<EndpointHeartbeat> heartbeats = heartbeatRepository.findAll();
		Instant since24h = Instant.now().minus(24, ChronoUnit.HOURS);

		long totalRequests = slotSnapshotRepository.sumRequestsSince(since24h);
		long totalBlocked = slotSnapshotRepository.sumBlockedRequestsSince(since24h);
		long distinctBlocked = clientEventRepository.countDistinctBlockedClientsSince(since24h);
		long totalMarked = slotSnapshotRepository.sumMarkedRequestsSince(since24h);
		long distinctMarked = clientEventRepository.countDistinctMarkedClientsSince(since24h);

		int online = (int) heartbeats.stream().filter(EndpointHeartbeat::online).count();
		int totalValves = heartbeats.stream().mapToInt(EndpointHeartbeat::valvesCount).sum();

		FleetSummary summary = new FleetSummary(
				heartbeats.size(),
				online,
				heartbeats.size() - online,
				totalValves,
				totalRequests,
				totalBlocked,
				distinctBlocked,
				totalMarked,
				distinctMarked
		);

		return Map.of(
				"summary", summary,
				"endpoints", heartbeats
		);
	}

	@GetMapping("/top-offenders")
	public List<TopOffenderSummary> topOffenders(
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "limit", defaultValue = "50") int limit) {
		Instant since = Instant.now().minus(hours, ChronoUnit.HOURS);
		return clientEventRepository.findTopOffenders(since, limit);
	}

	/**
	 * Export active blocked IP list for integration with external firewalls, fail2ban, or future Valve rules.
	 * Supports format=text (line-by-line IP list) or format=json.
	 */
	@GetMapping("/reputation/blocked-ips")
	public ResponseEntity<?> blockedIpReputation(
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "limit", defaultValue = "1000") int limit,
			@RequestParam(name = "format", defaultValue = "json") String format) {

		Instant since = Instant.now().minus(hours, ChronoUnit.HOURS);
		List<TopOffenderSummary> offenders = clientEventRepository.findTopOffenders(since, limit);

		if ("text".equalsIgnoreCase(format) || "txt".equalsIgnoreCase(format)) {
			StringBuilder sb = new StringBuilder();
			for (TopOffenderSummary o : offenders) {
				sb.append(o.clientKey()).append("\n");
			}
			return ResponseEntity.ok()
					.contentType(MediaType.TEXT_PLAIN)
					.body(sb.toString());
		}

		List<String> ipList = offenders.stream().map(TopOffenderSummary::clientKey).toList();
		return ResponseEntity.ok(Map.of(
				"generatedAt", Instant.now().toString(),
				"hoursWindow", hours,
				"count", ipList.size(),
				"blockedIps", ipList
		));
	}

	@GetMapping("/poll-log")
	public List<PollEventLog> pollLog(
			@RequestParam(name = "beforeId", required = false) Long beforeId,
			@RequestParam(name = "status", required = false) String status,
			@RequestParam(name = "serverId", required = false) String serverId,
			@RequestParam(name = "limit", defaultValue = "50") int limit) {
		return pollEventLogRepository.findRecent(beforeId, status, serverId, limit);
	}

	@GetMapping("/rollups/subnets")
	public Map<String, Object> subnetRollups(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "subnetQuery", required = false) String subnetQuery,
			@RequestParam(name = "asn", required = false) Long asn,
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			@RequestParam(name = "offset", defaultValue = "0") int offset) {

		Instant to = Instant.now();
		Instant from = to.minus(hours, ChronoUnit.HOURS);
		List<org.henbru.antidos.collector.model.ClientSubnetRollup> rollups = subnetRollupRepository.findRollupsFiltered(
				servers, valves, from, to, subnetQuery, asn, clientTypes, limit, offset
		);
		long total = subnetRollupRepository.countRollupsFiltered(
				servers, valves, from, to, subnetQuery, asn, clientTypes
		);

		return Map.of(
				"windowFrom", from.toString(),
				"windowTo", to.toString(),
				"totalCount", total,
				"limit", limit,
				"offset", offset,
				"rollups", rollups
		);
	}

	@org.springframework.web.bind.annotation.PostMapping("/rollups/subnets/aggregate")
	public Map<String, Object> triggerRollupAggregation(
			@RequestParam(name = "hours", defaultValue = "24") int hours) {
		int count = rollupAggregationService.aggregateCatchUp(hours);
		return Map.of(
				"status", "SUCCESS",
				"lookbackHours", hours,
				"persistedRollups", count,
				"executedAt", Instant.now().toString()
 		);
	}

	@org.springframework.web.bind.annotation.PostMapping("/rollups/subnets/profiles/refresh")
	public Map<String, Object> refreshSubnetProfiles() {
		if (subnetProfileService == null) {
			return Map.of("status", "UNAVAILABLE", "message", "SubnetProfileService is not available");
		}
		int count = subnetProfileService.refreshProfiles();
		return Map.of(
				"status", "SUCCESS",
				"refreshedProfiles", count,
				"executedAt", Instant.now().toString()
		);
	}

	@GetMapping("/rollups/subnets/profiles")
	public Map<String, Object> getSubnetProfiles(
			@RequestParam(name = "pattern", required = false, defaultValue = "ALL") String pattern,
			@RequestParam(name = "minRequests", required = false) Long minRequests,
			@RequestParam(name = "query", required = false) String query,
			@RequestParam(name = "asn", required = false) Long asn,
			@RequestParam(name = "asOrg", required = false) String asOrg,
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "sortBy", required = false, defaultValue = "SURGE") String sortBy,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			@RequestParam(name = "offset", defaultValue = "0") int offset) {
		if (subnetProfileService == null) {
			return Map.of("total", 0, "profiles", List.of());
		}
		List<org.henbru.antidos.collector.model.SubnetProfile> profiles = subnetProfileService.findProfilesFiltered(
				pattern, minRequests, query, asn, asOrg, clientTypes, sortBy, limit, offset);
		long total = subnetProfileService.countProfilesFiltered(
				pattern, minRequests, query, asn, asOrg, clientTypes);
		return Map.of(
				"total", total,
				"limit", limit,
				"offset", offset,
				"profiles", profiles
		);
	}

	@GetMapping("/rollups/subnets/profiles/{subnetGroup}")
	public ResponseEntity<org.henbru.antidos.collector.model.SubnetProfile> getSubnetProfile(
			@PathVariable(name = "subnetGroup") String subnetGroup) {
		if (subnetProfileService == null) {
			return ResponseEntity.notFound().build();
		}
		return subnetProfileService.findBySubnetGroup(subnetGroup)
				.map(ResponseEntity::ok)
				.orElseGet(() -> ResponseEntity.notFound().build());
	}

	@GetMapping("/analytics/overview")
	public org.henbru.antidos.collector.model.AnalyticsDashboardDto analyticsOverview(
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves) {
		return analyticsService.getDashboardAnalytics(hours, servers, valves);
	}

	@GetMapping("/analytics/timeline")
	public List<org.henbru.antidos.collector.model.TimelinePoint> analyticsTimeline(
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves) {
		return analyticsService.getDashboardAnalytics(hours, servers, valves).timeline();
	}

	@GetMapping("/analytics/composition")
	public List<org.henbru.antidos.collector.model.TrafficCompositionPoint> analyticsComposition(
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves) {
		return analyticsService.getDashboardAnalytics(hours, servers, valves).composition();
	}

	@GetMapping("/analytics/scatter")
	public List<org.henbru.antidos.collector.model.SubnetScatterPoint> analyticsScatter(
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves) {
		return analyticsService.getDashboardAnalytics(hours, servers, valves).scatterPoints();
	}

	@GetMapping("/valves")
	public List<org.henbru.antidos.collector.model.MonitoredValve> listValves(
			@RequestParam(name = "serverId", required = false) String serverId,
			@RequestParam(name = "activeOnly", required = false, defaultValue = "false") boolean activeOnly) {
		if (monitoredValveRepository == null) {
			return List.of();
		}
		List<org.henbru.antidos.collector.model.MonitoredValve> list;
		if (serverId != null && !serverId.isBlank()) {
			list = monitoredValveRepository.findByServerId(serverId.trim());
		} else {
			list = monitoredValveRepository.findAll();
		}
		if (activeOnly) {
			return list.stream().filter(org.henbru.antidos.collector.model.MonitoredValve::isActive).toList();
		}
		return list;
	}

	@GetMapping("/valves/{valveName}")
	public ResponseEntity<org.henbru.antidos.collector.model.MonitoredValve> getValve(
			@RequestParam(name = "serverId") String serverId,
			@PathVariable(name = "valveName") String valveName) {
		if (monitoredValveRepository == null) {
			return ResponseEntity.notFound().build();
		}
		return monitoredValveRepository.findByServerIdAndValveName(serverId, valveName)
				.map(ResponseEntity::ok)
				.orElseGet(() -> ResponseEntity.notFound().build());
	}
}
