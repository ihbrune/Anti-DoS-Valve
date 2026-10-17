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

	public ApiController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository) {
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.pollEventLogRepository = pollEventLogRepository;
	}

	@GetMapping("/fleet")
	public Map<String, Object> fleetOverview() {
		List<EndpointHeartbeat> heartbeats = heartbeatRepository.findAll();
		Instant since24h = Instant.now().minus(24, ChronoUnit.HOURS);

		long totalRequests = slotSnapshotRepository.sumRequestsSince(since24h);
		long totalBlocked = slotSnapshotRepository.sumBlockedRequestsSince(since24h);
		long distinctBlocked = clientEventRepository.countDistinctBlockedClientsSince(since24h);

		int online = (int) heartbeats.stream().filter(EndpointHeartbeat::online).count();
		int totalValves = heartbeats.stream().mapToInt(EndpointHeartbeat::valvesCount).sum();

		FleetSummary summary = new FleetSummary(
				heartbeats.size(),
				online,
				heartbeats.size() - online,
				totalValves,
				totalRequests,
				totalBlocked,
				distinctBlocked
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
}
