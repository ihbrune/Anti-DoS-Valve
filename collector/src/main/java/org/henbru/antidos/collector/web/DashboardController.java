package org.henbru.antidos.collector.web;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.docs.DocumentationService;
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
	private final DocumentationService documentationService;
	private final org.henbru.antidos.collector.config.CollectorProperties properties;
	private final org.henbru.antidos.collector.config.ValveRuleResolver valveRuleResolver;

	@org.springframework.beans.factory.annotation.Autowired
	public DashboardController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			DocumentationService documentationService,
			org.henbru.antidos.collector.config.CollectorProperties properties,
			org.henbru.antidos.collector.config.ValveRuleResolver valveRuleResolver) {
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.pollEventLogRepository = pollEventLogRepository;
		this.documentationService = documentationService;
		this.properties = properties;
		this.valveRuleResolver = valveRuleResolver != null ? valveRuleResolver : new org.henbru.antidos.collector.config.ValveRuleResolver(properties);
	}

	public DashboardController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			DocumentationService documentationService,
			org.henbru.antidos.collector.config.CollectorProperties properties) {
		this(heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				documentationService, properties, new org.henbru.antidos.collector.config.ValveRuleResolver(properties));
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

	@GetMapping("/help")
	public String helpPage(Model model) {
		DocumentationService.DocumentationPayload payload = documentationService.getDocumentation();
		model.addAttribute("docHtml", payload.html());
		model.addAttribute("docToc", payload.tableOfContents());
		return "help";
	}

	@GetMapping("/fragments/help")
	public String helpFragment(Model model) {
		DocumentationService.DocumentationPayload payload = documentationService.getDocumentation();
		model.addAttribute("docHtml", payload.html());
		model.addAttribute("docToc", payload.tableOfContents());
		return "help :: docContent";
	}

	@GetMapping("/fragments/stats-overview")
	public String statsOverviewFragment(Model model) {
		List<EndpointHeartbeat> heartbeats = heartbeatRepository.findAll();
		model.addAttribute("fleetSummary", buildFleetSummary(heartbeats));
		return "fragments/stats-overview :: statsOverview";
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
		List<ClientEvent> events = clientEventRepository.findRecentEvents(serverId, filterIp, limit);
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
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "asn", required = false) String asn,
			@RequestParam(name = "status", required = false) String status,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			Model model) {
		populateEventsModel(servers, valves, fromStr, toStr, clientQuery, clientTypes, asn, status, limit, 0, model);
		return "events";
	}

	@GetMapping("/fragments/events-table")
	public String eventsTableFragment(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "from", required = false) String fromStr,
			@RequestParam(name = "to", required = false) String toStr,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "asn", required = false) String asn,
			@RequestParam(name = "status", required = false) String status,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			@RequestParam(name = "offset", defaultValue = "0") int offset,
			Model model) {
		populateEventsModel(servers, valves, fromStr, toStr, clientQuery, clientTypes, asn, status, limit, offset, model);
		return "fragments/events-table :: eventsTable";
	}

	@GetMapping("/offenders")
	public String offendersPage(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "from", required = false) String fromStr,
			@RequestParam(name = "to", required = false) String toStr,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "asn", required = false) String asn,
			@RequestParam(name = "status", required = false) String status,
			@RequestParam(name = "groupBy", defaultValue = "CLIENT") String groupBy,
			@RequestParam(name = "limit", defaultValue = "25") int limit,
			Model model) {
		populateOffendersModel(servers, valves, fromStr, toStr, clientQuery, clientTypes, asn, status, groupBy, limit, model);
		return "offenders";
	}

	@GetMapping("/fragments/offenders-table")
	public String offendersTableFragment(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "from", required = false) String fromStr,
			@RequestParam(name = "to", required = false) String toStr,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "asn", required = false) String asn,
			@RequestParam(name = "status", required = false) String status,
			@RequestParam(name = "groupBy", defaultValue = "CLIENT") String groupBy,
			@RequestParam(name = "limit", defaultValue = "25") int limit,
			Model model) {
		populateOffendersModel(servers, valves, fromStr, toStr, clientQuery, clientTypes, asn, status, groupBy, limit, model);
		return "fragments/offenders-table :: offenderTable";
	}

	@GetMapping("/server/{serverId}")
	public String serverDetails(
			@PathVariable(name = "serverId") String serverId,
			@RequestParam(name = "valve", required = false) String valve,
			Model model) {
		EndpointHeartbeat hb = heartbeatRepository.findByServerId(serverId).orElse(null);
		List<SlotSnapshot> recentSlots = slotSnapshotRepository.findRecent(serverId, valve, 50);
		List<ClientEvent> recentEvents = clientEventRepository.findRecentEvents(serverId, null, 100);

		Instant minStartTime = recentSlots.isEmpty() ? null : recentSlots.get(recentSlots.size() - 1).startTime();
		List<ClientEvent> slotEvents = (minStartTime != null)
				? clientEventRepository.findRecentEventsFiltered(
						List.of(serverId),
						valve != null ? List.of(valve) : null,
						minStartTime,
						null,
						null,
						500,
						0)
				: recentEvents;

		Map<String, List<ClientEvent>> slotEventsMap = new HashMap<>();
		for (ClientEvent event : slotEvents) {
			String key = event.valveName() + "_" + event.slotKey();
			slotEventsMap.computeIfAbsent(key, k -> new ArrayList<>()).add(event);
		}

		// Resolve valves and active tracking rules for this server
		org.henbru.antidos.collector.config.EndpointConfig endpoint = properties.getEndpoints().stream()
				.filter(e -> e != null && e.getName() != null && e.getName().equalsIgnoreCase(serverId))
				.findFirst()
				.orElse(null);

		java.util.Set<String> valveNames = new java.util.LinkedHashSet<>();
		if (endpoint != null && endpoint.getValves() != null) {
			for (org.henbru.antidos.collector.config.EndpointValveConfig v : endpoint.getValves()) {
				if (v.getName() != null && !v.getName().isBlank()) {
					valveNames.add(v.getName().trim());
				}
			}
		}
		List<String> distinctValves = slotSnapshotRepository.findDistinctValvesForServer(serverId);
		valveNames.addAll(distinctValves);

		List<org.henbru.antidos.collector.config.EffectiveValveRule> configuredValves = new ArrayList<>();
		for (String vName : valveNames) {
			configuredValves.add(valveRuleResolver.resolve(endpoint, vName));
		}

		model.addAttribute("server", hb);
		model.addAttribute("serverId", serverId);
		model.addAttribute("endpointConfig", endpoint);
		model.addAttribute("configuredValves", configuredValves);
		model.addAttribute("selectedValve", valve);
		model.addAttribute("recentSlots", recentSlots);
		model.addAttribute("recentEvents", recentEvents);
		model.addAttribute("slotEventsMap", slotEventsMap);
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
		long totalPolls24h = pollEventLogRepository.countSince(since24h);
		long errorCount24h = pollEventLogRepository.countByStatusSince("ERROR", since24h);
		long warningCount24h = pollEventLogRepository.countByStatusSince("WARNING", since24h);
		List<EndpointHeartbeat> heartbeats = heartbeatRepository.findAll();

		model.addAttribute("entries", entries);
		model.addAttribute("hasMore", hasMore);
		model.addAttribute("nextBeforeId", nextBeforeId);
		model.addAttribute("selectedStatus", status);
		model.addAttribute("selectedServer", serverId != null ? serverId : "");
		model.addAttribute("heartbeats", heartbeats);
		model.addAttribute("totalPolls24h", totalPolls24h);
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
		List<ClientEvent> recentEvents = clientEventRepository.findRecentEvents(null, null, 50);
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
			List<String> clientTypes,
			String asnStr,
			String status,
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

		Long parsedAsn = parseAsn(asnStr);
		String normalizedStatus = (status != null && !status.isBlank() && !"ALL".equalsIgnoreCase(status.trim()))
				? status.trim().toUpperCase()
				: null;

		List<ClientEvent> events = clientEventRepository.findRecentEventsFiltered(
				servers, valves, fromTime, toTime, clientQuery, clientTypes, parsedAsn, normalizedStatus, limit, offset);
		long totalCount = clientEventRepository.countRecentEventsFiltered(
				servers, valves, fromTime, toTime, clientQuery, clientTypes, parsedAsn, normalizedStatus);

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
		model.addAttribute("selectedTypes", clientTypes != null ? clientTypes : List.of());
		model.addAttribute("selectedAsn", asnStr != null ? asnStr : "");
		model.addAttribute("selectedStatus", status != null ? status : "ALL");
	}

	private void populateOffendersModel(
			List<String> servers,
			List<String> valves,
			String fromStr,
			String toStr,
			String clientQuery,
			List<String> clientTypes,
			String asnStr,
			String status,
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

		Long parsedAsn = parseAsn(asnStr);
		String normalizedStatus = (status != null && !status.isBlank() && !"ALL".equalsIgnoreCase(status.trim()))
				? status.trim().toUpperCase()
				: null;

		String effectiveGroupBy = "ASN".equalsIgnoreCase(groupBy) ? "ASN" : ("SUBNET".equalsIgnoreCase(groupBy) ? "SUBNET" : "CLIENT");
		List<TopOffenderSummary> topOffenders = clientEventRepository.findTopOffendersFiltered(
				servers, valves, fromTime, toTime, clientQuery, clientTypes, parsedAsn, normalizedStatus, effectiveGroupBy, limit);

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
		model.addAttribute("selectedTypes", clientTypes != null ? clientTypes : List.of());
		model.addAttribute("selectedAsn", asnStr != null ? asnStr : "");
		model.addAttribute("selectedStatus", status != null ? status : "ALL");
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

	private Long parseAsn(String input) {
		if (input == null || input.trim().isEmpty()) {
			return null;
		}
		String s = input.trim();
		if (s.regionMatches(true, 0, "AS", 0, 2)) {
			s = s.substring(2).trim();
		}
		try {
			return Long.valueOf(s);
		} catch (NumberFormatException e) {
			return null;
		}
	}
}
