package org.henbru.antidos.collector.web;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.FleetSummary;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controller serving the main Web UI, specialized forensic investigation views, and dynamic HTMX fragments.
 */
@Controller
@SuppressWarnings("null")
public class DashboardController {

	private static final DateTimeFormatter LOCAL_DT_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm");

	private final HeartbeatRepository heartbeatRepository;
	private final SlotSnapshotRepository slotSnapshotRepository;
	private final ClientEventRepository clientEventRepository;
	private final PollEventLogRepository pollEventLogRepository;
	private final org.henbru.antidos.collector.config.CollectorProperties properties;

	public DashboardController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.config.CollectorProperties properties) {
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.pollEventLogRepository = pollEventLogRepository;
		this.properties = properties;
	}

	@org.springframework.web.bind.annotation.ModelAttribute("demoMode")
	public boolean demoMode() {
		return properties.isDemoMode();
	}

	@GetMapping("/")
	public String index(Model model) {
		populateDashboardModel(model);
		return "index";
	}

	@GetMapping("/fragments/fleet")
	public String fleetFragment(Model model) {
		List<EndpointHeartbeat> heartbeats = heartbeatRepository.findAll();
		model.addAttribute("heartbeats", heartbeats);
		model.addAttribute("fleetSummary", buildFleetSummary(heartbeats));
		return "fragments/fleet :: fleetList";
	}

	@GetMapping("/fragments/top-offenders")
	public String topOffendersFragment(
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "limit", defaultValue = "25") int limit,
			Model model) {
		Instant since = Instant.now().minus(hours, ChronoUnit.HOURS);
		List<TopOffenderSummary> offenders = clientEventRepository.findTopOffenders(since, limit);
		model.addAttribute("topOffenders", offenders);
		model.addAttribute("selectedHours", hours);
		return "fragments/top-offenders :: offenderTable";
	}

	@GetMapping("/fragments/recent-events")
	public String recentEventsFragment(
			@RequestParam(name = "serverId", required = false) String serverId,
			@RequestParam(name = "filterIp", required = false) String filterIp,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			Model model) {
		List<BlockedClientEvent> events = clientEventRepository.findRecentEvents(serverId, filterIp, limit);
		model.addAttribute("recentEvents", events);
		model.addAttribute("selectedServer", serverId);
		model.addAttribute("filterIp", filterIp);
		return "fragments/recent-events :: eventsTable";
	}

	@GetMapping("/events")
	public String eventsPage(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "from", required = false) String fromStr,
			@RequestParam(name = "to", required = false) String toStr,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			Model model) {
		populateEventsModel(servers, valves, fromStr, toStr, clientQuery, limit, 0, model);
		return "events";
	}

	@GetMapping("/fragments/events-table")
	public String eventsTableFragment(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "from", required = false) String fromStr,
			@RequestParam(name = "to", required = false) String toStr,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			@RequestParam(name = "offset", defaultValue = "0") int offset,
			Model model) {
		populateEventsModel(servers, valves, fromStr, toStr, clientQuery, limit, offset, model);
		return "fragments/events-table :: eventsTable";
	}

	@GetMapping("/offenders")
	public String offendersPage(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "from", required = false) String fromStr,
			@RequestParam(name = "to", required = false) String toStr,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "groupBy", defaultValue = "CLIENT") String groupBy,
			@RequestParam(name = "limit", defaultValue = "25") int limit,
			Model model) {
		populateOffendersModel(servers, valves, fromStr, toStr, clientQuery, groupBy, limit, model);
		return "offenders";
	}

	@GetMapping("/fragments/offenders-table")
	public String offendersTableFragment(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "from", required = false) String fromStr,
			@RequestParam(name = "to", required = false) String toStr,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "groupBy", defaultValue = "CLIENT") String groupBy,
			@RequestParam(name = "limit", defaultValue = "25") int limit,
			Model model) {
		populateOffendersModel(servers, valves, fromStr, toStr, clientQuery, groupBy, limit, model);
		return "fragments/offenders-table :: offenderTable";
	}

	@GetMapping("/server/{serverId}")
	public String serverDetails(@PathVariable(name = "serverId") String serverId, Model model) {
		EndpointHeartbeat hb = heartbeatRepository.findByServerId(serverId).orElse(null);
		List<SlotSnapshot> recentSlots = slotSnapshotRepository.findRecent(serverId, "", 50);
		List<BlockedClientEvent> recentEvents = clientEventRepository.findRecentEvents(serverId, null, 100);

		model.addAttribute("server", hb);
		model.addAttribute("serverId", serverId);
		model.addAttribute("recentSlots", recentSlots);
		model.addAttribute("recentEvents", recentEvents);
		return "server-details";
	}

	@GetMapping("/poll-log")
	public String pollLog(
			@RequestParam(name = "status", required = false, defaultValue = "ALL") String status,
			@RequestParam(name = "serverId", required = false) String serverId,
			Model model) {
		int limit = 30;
		List<PollEventLog> entries = pollEventLogRepository.findRecent(null, status, serverId, limit);
		boolean hasMore = entries.size() >= limit;
		Long nextBeforeId = hasMore && !entries.isEmpty() ? entries.getLast().id() : null;

		Instant since24h = Instant.now().minus(24, ChronoUnit.HOURS);
		long errorCount24h = pollEventLogRepository.countByStatusSince("ERROR", since24h);
		long warningCount24h = pollEventLogRepository.countByStatusSince("WARNING", since24h);
		List<EndpointHeartbeat> heartbeats = heartbeatRepository.findAll();

		model.addAttribute("entries", entries);
		model.addAttribute("hasMore", hasMore);
		model.addAttribute("nextBeforeId", nextBeforeId);
		model.addAttribute("selectedStatus", status);
		model.addAttribute("selectedServer", serverId != null ? serverId : "");
		model.addAttribute("heartbeats", heartbeats);
		model.addAttribute("errorCount24h", errorCount24h);
		model.addAttribute("warningCount24h", warningCount24h);
		return "poll-log";
	}

	@GetMapping("/fragments/poll-log")
	public String pollLogFragment(
			@RequestParam(name = "beforeId", required = false) Long beforeId,
			@RequestParam(name = "status", required = false, defaultValue = "ALL") String status,
			@RequestParam(name = "serverId", required = false) String serverId,
			@RequestParam(name = "limit", defaultValue = "30") int limit,
			Model model) {
		List<PollEventLog> entries = pollEventLogRepository.findRecent(beforeId, status, serverId, limit);
		boolean hasMore = entries.size() >= limit;
		Long nextBeforeId = hasMore && !entries.isEmpty() ? entries.getLast().id() : null;

		model.addAttribute("entries", entries);
		model.addAttribute("hasMore", hasMore);
		model.addAttribute("nextBeforeId", nextBeforeId);
		model.addAttribute("selectedStatus", status);
		model.addAttribute("selectedServer", serverId != null ? serverId : "");
		return "fragments/poll-log :: logRows";
	}

	private void populateDashboardModel(Model model) {
		List<EndpointHeartbeat> heartbeats = heartbeatRepository.findAll();
		Instant since24h = Instant.now().minus(24, ChronoUnit.HOURS);

		List<TopOffenderSummary> topOffenders = clientEventRepository.findTopOffenders(since24h, 25);
		List<BlockedClientEvent> recentEvents = clientEventRepository.findRecentEvents(null, null, 50);
		List<SlotSnapshot> recentSlots = slotSnapshotRepository.findRecentFleet(20);

		model.addAttribute("heartbeats", heartbeats);
		model.addAttribute("fleetSummary", buildFleetSummary(heartbeats));
		model.addAttribute("topOffenders", topOffenders);
		model.addAttribute("recentEvents", recentEvents);
		model.addAttribute("recentSlots", recentSlots);
	}

	private void populateEventsModel(
			List<String> servers,
			List<String> valves,
			String fromStr,
			String toStr,
			String clientQuery,
			int limit,
			int offset,
			Model model) {

		Instant now = Instant.now();
		Instant fromTime = parseDateTime(fromStr);
		Instant toTime = parseDateTime(toStr);

		if (fromTime == null && toTime == null) {
			fromTime = now.minus(24, ChronoUnit.HOURS);
			toTime = now;
		}

		List<BlockedClientEvent> events = clientEventRepository.findRecentEventsFiltered(
				servers, valves, fromTime, toTime, clientQuery, limit, offset);
		long totalCount = clientEventRepository.countRecentEventsFiltered(
				servers, valves, fromTime, toTime, clientQuery);

		boolean hasMore = (offset + events.size()) < totalCount;
		int nextOffset = offset + limit;

		model.addAttribute("events", events);
		model.addAttribute("totalCount", totalCount);
		model.addAttribute("hasMore", hasMore);
		model.addAttribute("nextOffset", nextOffset);
		model.addAttribute("limit", limit);

		model.addAttribute("availableServers", getAvailableServerIds());
		model.addAttribute("availableValves", getAvailableValveNames(servers));
		model.addAttribute("selectedServers", servers != null ? servers : List.of());
		model.addAttribute("selectedValves", valves != null ? valves : List.of());
		model.addAttribute("fromTime", formatDateTimeLocal(fromTime));
		model.addAttribute("toTime", formatDateTimeLocal(toTime));
		model.addAttribute("clientQuery", clientQuery != null ? clientQuery : "");
	}

	private void populateOffendersModel(
			List<String> servers,
			List<String> valves,
			String fromStr,
			String toStr,
			String clientQuery,
			String groupBy,
			int limit,
			Model model) {

		Instant now = Instant.now();
		Instant fromTime = parseDateTime(fromStr);
		Instant toTime = parseDateTime(toStr);

		if (fromTime == null && toTime == null) {
			fromTime = now.minus(24, ChronoUnit.HOURS);
			toTime = now;
		}

		String effectiveGroupBy = "SUBNET".equalsIgnoreCase(groupBy) ? "SUBNET" : "CLIENT";
		List<TopOffenderSummary> topOffenders = clientEventRepository.findTopOffendersFiltered(
				servers, valves, fromTime, toTime, clientQuery, effectiveGroupBy, limit);

		model.addAttribute("topOffenders", topOffenders);
		model.addAttribute("groupBy", effectiveGroupBy);
		model.addAttribute("limit", limit);

		model.addAttribute("availableServers", getAvailableServerIds());
		model.addAttribute("availableValves", getAvailableValveNames(servers));
		model.addAttribute("selectedServers", servers != null ? servers : List.of());
		model.addAttribute("selectedValves", valves != null ? valves : List.of());
		model.addAttribute("fromTime", formatDateTimeLocal(fromTime));
		model.addAttribute("toTime", formatDateTimeLocal(toTime));
		model.addAttribute("clientQuery", clientQuery != null ? clientQuery : "");
	}

	private List<String> getAvailableServerIds() {
		List<String> serverIds = new ArrayList<>(clientEventRepository.findDistinctServerIds());
		for (EndpointHeartbeat hb : heartbeatRepository.findAll()) {
			if (!serverIds.contains(hb.serverId())) {
				serverIds.add(hb.serverId());
			}
		}
		serverIds.sort(String::compareTo);
		return serverIds;
	}

	private List<String> getAvailableValveNames(List<String> servers) {
		return clientEventRepository.findDistinctValveNames(servers);
	}

	private Instant parseDateTime(String input) {
		if (input == null || input.trim().isEmpty()) {
			return null;
		}
		try {
			return LocalDateTime.parse(input.trim()).atZone(ZoneId.systemDefault()).toInstant();
		} catch (Exception e) {
			return null;
		}
	}

	private String formatDateTimeLocal(Instant instant) {
		if (instant == null) {
			return "";
		}
		return LOCAL_DT_FORMATTER.format(instant.atZone(ZoneId.systemDefault()));
	}

	private FleetSummary buildFleetSummary(List<EndpointHeartbeat> heartbeats) {
		Instant since24h = Instant.now().minus(24, ChronoUnit.HOURS);
		int totalEndpoints = heartbeats.size();
		int online = (int) heartbeats.stream().filter(EndpointHeartbeat::online).count();
		int offline = totalEndpoints - online;
		int totalValves = heartbeats.stream().mapToInt(EndpointHeartbeat::valvesCount).sum();

		long totalRequests = slotSnapshotRepository.sumRequestsSince(since24h);
		long totalBlocked = slotSnapshotRepository.sumBlockedRequestsSince(since24h);
		long distinctBlocked = clientEventRepository.countDistinctBlockedClientsSince(since24h);

		return new FleetSummary(
				totalEndpoints,
				online,
				offline,
				totalValves,
				totalRequests,
				totalBlocked,
				distinctBlocked
		);
	}
}
