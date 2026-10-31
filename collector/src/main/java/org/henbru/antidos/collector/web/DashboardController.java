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
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.henbru.antidos.collector.docs.DocumentationService;
import org.henbru.antidos.collector.model.ClientEvent;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.core.JsonProcessingException;

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
	private final org.henbru.antidos.collector.storage.SubnetRollupRepository subnetRollupRepository;
	private final DocumentationService documentationService;
	private final org.henbru.antidos.collector.config.CollectorProperties properties;
	private final org.henbru.antidos.collector.config.ValveRuleResolver valveRuleResolver;
	private final org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository;
	private final org.henbru.antidos.collector.aggregation.AnalyticsService analyticsService;
	private final com.fasterxml.jackson.databind.ObjectMapper objectMapper;
	private final org.henbru.antidos.collector.annotation.NetworkAnnotationService annotationService;
	private final org.henbru.antidos.collector.aggregation.SubnetProfileService subnetProfileService;
	private final org.henbru.antidos.collector.poller.CollectorPollerService collectorPollerService;
	private final org.henbru.antidos.collector.aggregation.RollupAggregationService rollupAggregationService;

	@org.springframework.beans.factory.annotation.Autowired
	public DashboardController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.storage.SubnetRollupRepository subnetRollupRepository,
			DocumentationService documentationService,
			org.henbru.antidos.collector.config.CollectorProperties properties,
			org.henbru.antidos.collector.config.ValveRuleResolver valveRuleResolver,
			@org.springframework.beans.factory.annotation.Autowired(required = false)
			org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository,
			@org.springframework.beans.factory.annotation.Autowired(required = false)
			org.henbru.antidos.collector.aggregation.AnalyticsService analyticsService,
			@org.springframework.beans.factory.annotation.Autowired(required = false)
			com.fasterxml.jackson.databind.ObjectMapper objectMapper,
			@org.springframework.beans.factory.annotation.Autowired(required = false)
			org.henbru.antidos.collector.annotation.NetworkAnnotationService annotationService,
			@org.springframework.beans.factory.annotation.Autowired(required = false)
			org.henbru.antidos.collector.aggregation.SubnetProfileService subnetProfileService,
			@org.springframework.beans.factory.annotation.Autowired(required = false)
			org.henbru.antidos.collector.poller.CollectorPollerService collectorPollerService,
			@org.springframework.beans.factory.annotation.Autowired(required = false)
			org.henbru.antidos.collector.aggregation.RollupAggregationService rollupAggregationService) {
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.pollEventLogRepository = pollEventLogRepository;
		this.subnetRollupRepository = subnetRollupRepository;
		this.documentationService = documentationService;
		this.properties = properties;
		this.valveRuleResolver = valveRuleResolver != null ? valveRuleResolver : new org.henbru.antidos.collector.config.ValveRuleResolver(properties);
		this.monitoredValveRepository = monitoredValveRepository;
		this.analyticsService = analyticsService;
		this.objectMapper = objectMapper != null ? objectMapper : new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules();
		this.annotationService = annotationService;
		this.subnetProfileService = subnetProfileService;
		this.collectorPollerService = collectorPollerService;
		this.rollupAggregationService = rollupAggregationService;
	}

	public DashboardController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.storage.SubnetRollupRepository subnetRollupRepository,
			DocumentationService documentationService,
			org.henbru.antidos.collector.config.CollectorProperties properties,
			org.henbru.antidos.collector.config.ValveRuleResolver valveRuleResolver) {
		this(heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				subnetRollupRepository, documentationService, properties, valveRuleResolver, null, null, null, null, null, null, null);
	}

	public DashboardController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.storage.SubnetRollupRepository subnetRollupRepository,
			DocumentationService documentationService,
			org.henbru.antidos.collector.config.CollectorProperties properties) {
		this(heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				subnetRollupRepository, documentationService, properties, new org.henbru.antidos.collector.config.ValveRuleResolver(properties), null, null, null, null, null, null, null);
	}

	@org.springframework.web.bind.annotation.ModelAttribute("demoMode")
	public boolean demoMode() {
		return properties.isDemoMode();
	}

	@org.springframework.web.bind.annotation.ModelAttribute("asnAnnotations")
	public Map<Long, org.henbru.antidos.collector.model.NetworkAnnotation> asnAnnotations() {
		return annotationService != null ? annotationService.getAsnAnnotationMap() : Map.of();
	}

	@org.springframework.web.bind.annotation.ModelAttribute("subnetAnnotations")
	public Map<String, org.henbru.antidos.collector.model.NetworkAnnotation> subnetAnnotations() {
		return annotationService != null ? annotationService.getSubnetAnnotationMap() : Map.of();
	}

	@GetMapping("/")
	public String index(Model model) {
		populateDashboardModel(model);
		return "index";
	}

	@GetMapping("/help")
	public String helpPage(
			@RequestParam(name = "doc", defaultValue = "ui") String docKey,
			Model model) {
		DocumentationService.DocumentationPayload payload = documentationService.getDocumentation(docKey);
		model.addAttribute("activeDoc", payload.docKey());
		model.addAttribute("docTitle", payload.title());
		model.addAttribute("docHtml", payload.html());
		model.addAttribute("docToc", payload.tableOfContents());
		return "help";
	}

	@GetMapping("/fragments/help")
	public String helpFragment(
			@RequestParam(name = "doc", defaultValue = "ui") String docKey,
			@RequestParam(name = "section", required = false) String section,
			Model model) {
		if (section != null && !section.isBlank()) {
			String sectionHtml = documentationService.getSectionHtml(docKey, section);
			model.addAttribute("docHtml", sectionHtml);
			model.addAttribute("activeDoc", docKey);
			model.addAttribute("sectionAnchor", section);
			return "fragments/help-drawer :: drawerContent";
		}
		DocumentationService.DocumentationPayload payload = documentationService.getDocumentation(docKey);
		model.addAttribute("activeDoc", payload.docKey());
		model.addAttribute("docTitle", payload.title());
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

	@GetMapping("/analytics")
	public String analyticsPage(
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "tab", defaultValue = "charts") String tab,
			Model model) {
		populateAnalyticsModel(servers, valves, hours, tab, model);
		return "analytics";
	}

	@GetMapping("/fragments/analytics-overview")
	public String analyticsOverviewFragment(
			@RequestParam(name = "hours", defaultValue = "24") int hours,
			@RequestParam(name = "servers", required = false) List<String> servers,
			@RequestParam(name = "valves", required = false) List<String> valves,
			@RequestParam(name = "tab", defaultValue = "charts") String tab,
			Model model) {
		populateAnalyticsModel(servers, valves, hours, tab, model);
		return "fragments/analytics-overview :: analyticsCard";
	}

	private void populateAnalyticsModel(
			List<String> servers,
			List<String> valves,
			int hours,
			String tab,
			Model model) {
		if (analyticsService != null) {
			org.henbru.antidos.collector.model.AnalyticsDashboardDto analytics =
					analyticsService.getDashboardAnalytics(hours, servers, valves);
			model.addAttribute("analytics", analytics);
			model.addAttribute("analyticsJson", toJson(analytics));
		}
		model.addAttribute("selectedHours", hours);
		model.addAttribute("activeTab", tab != null ? tab : "charts");
		model.addAttribute("availableServers", getAvailableServerIds());
		model.addAttribute("availableValves", getAvailableValveNames(servers));
		model.addAttribute("selectedServers", servers != null ? servers : List.of());
		model.addAttribute("selectedValves", valves != null ? valves : List.of());
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
			@RequestParam(name = "status", required = false, defaultValue = "BLOCKED") String status,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			Model model) {
		List<ClientEvent> events = clientEventRepository.findRecentEvents(serverId, filterIp, status, limit);
		model.addAttribute("recentEvents", events);
		model.addAttribute("selectedServer", serverId);
		model.addAttribute("filterIp", filterIp);
		model.addAttribute("selectedStatus", status);
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
			@RequestParam(name = "activityPattern", required = false, defaultValue = "ALL") String activityPattern,
			@RequestParam(name = "minRequests", required = false) Long minRequests,
			@RequestParam(name = "sortBy", required = false) String sortBy,
			@RequestParam(name = "limit", defaultValue = "25") int limit,
			Model model) {
		populateOffendersModel(servers, valves, fromStr, toStr, clientQuery, clientTypes, asn, status, groupBy, activityPattern, minRequests, sortBy, limit, model);
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
			@RequestParam(name = "activityPattern", required = false, defaultValue = "ALL") String activityPattern,
			@RequestParam(name = "minRequests", required = false) Long minRequests,
			@RequestParam(name = "sortBy", required = false) String sortBy,
			@RequestParam(name = "limit", defaultValue = "25") int limit,
			Model model) {
		populateOffendersModel(servers, valves, fromStr, toStr, clientQuery, clientTypes, asn, status, groupBy, activityPattern, minRequests, sortBy, limit, model);
		return "fragments/offenders-table :: offenderTable";
	}

	@GetMapping("/profiles")
	public String profilesPage(
			@RequestParam(name = "activityPattern", required = false, defaultValue = "ALL") String activityPattern,
			@RequestParam(name = "minRequests", required = false) Long minRequests,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "asn", required = false) String asn,
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "sortBy", required = false, defaultValue = "SURGE") String sortBy,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			@RequestParam(name = "offset", defaultValue = "0") int offset,
			Model model) {
		populateProfilesModel(activityPattern, minRequests, clientQuery, asn, clientTypes, sortBy, limit, offset, model);
		return "profiles";
	}

	@GetMapping("/fragments/profiles-table")
	public String profilesTableFragment(
			@RequestParam(name = "activityPattern", required = false, defaultValue = "ALL") String activityPattern,
			@RequestParam(name = "minRequests", required = false) Long minRequests,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "asn", required = false) String asn,
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "sortBy", required = false, defaultValue = "SURGE") String sortBy,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			@RequestParam(name = "offset", defaultValue = "0") int offset,
			Model model) {
		populateProfilesModel(activityPattern, minRequests, clientQuery, asn, clientTypes, sortBy, limit, offset, model);
		return "fragments/profiles-table :: profilesTable";
	}

	@org.springframework.web.bind.annotation.PostMapping("/profiles/refresh")
	public String refreshProfiles(
			@RequestParam(name = "activityPattern", required = false, defaultValue = "ALL") String activityPattern,
			@RequestParam(name = "minRequests", required = false) Long minRequests,
			@RequestParam(name = "clientQuery", required = false) String clientQuery,
			@RequestParam(name = "asn", required = false) String asn,
			@RequestParam(name = "clientTypes", required = false) List<String> clientTypes,
			@RequestParam(name = "sortBy", required = false, defaultValue = "SURGE") String sortBy,
			@RequestParam(name = "limit", defaultValue = "50") int limit,
			@RequestParam(name = "offset", defaultValue = "0") int offset,
			Model model) {
		if (rollupAggregationService != null) {
			try {
				rollupAggregationService.executeManualCatchUp(6);
			} catch (Exception ignored) {
			}
		} else if (subnetProfileService != null) {
			try {
				subnetProfileService.refreshProfiles();
			} catch (Exception ignored) {
			}
		}
		populateProfilesModel(activityPattern, minRequests, clientQuery, asn, clientTypes, sortBy, limit, offset, model);
		return "redirect:/profiles";
	}

	@GetMapping("/server/{serverId}")
	public String serverDetails(
			@PathVariable(name = "serverId") String serverId,
			@RequestParam(name = "valve", required = false) String valve,
			@RequestParam(name = "status", required = false, defaultValue = "ALL") String status,
			Model model) {
		String effectiveStatus = (status != null && !status.isBlank()) ? status.trim().toUpperCase() : "ALL";
		if (!"BLOCKED".equals(effectiveStatus) && !"ACTIVE".equals(effectiveStatus)) {
			effectiveStatus = "ALL";
		}
		String effectiveValve = (valve != null && !valve.isBlank()) ? valve.trim() : null;

		EndpointHeartbeat hb = heartbeatRepository.findByServerId(serverId).orElse(null);
		List<SlotSnapshot> recentSlots = slotSnapshotRepository.findRecent(serverId, effectiveValve, 50);
		List<ClientEvent> recentEvents = clientEventRepository.findRecentEventsFiltered(
				List.of(serverId),
				effectiveValve != null ? List.of(effectiveValve) : null,
				null,
				null,
				null,
				null,
				null,
				null,
				effectiveStatus,
				100,
				0);

		Instant minStartTime = recentSlots.isEmpty() ? null : recentSlots.get(recentSlots.size() - 1).startTime();
		List<ClientEvent> slotEvents = (minStartTime != null)
				? clientEventRepository.findRecentEventsFiltered(
						List.of(serverId),
						effectiveValve != null ? List.of(effectiveValve) : null,
						minStartTime,
						null,
						null,
						null,
						null,
						null,
						"BLOCKED",
						500,
						0)
				: ("BLOCKED".equals(effectiveStatus)
						? recentEvents
						: clientEventRepository.findRecentEventsFiltered(
								List.of(serverId),
								effectiveValve != null ? List.of(effectiveValve) : null,
								null,
								null,
								null,
								null,
								null,
								null,
								"BLOCKED",
								100,
								0));

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

		List<org.henbru.antidos.collector.model.MonitoredValve> runtimeValves =
				(monitoredValveRepository != null) ? monitoredValveRepository.findByServerId(serverId) : List.of();
		java.util.Map<String, org.henbru.antidos.collector.model.MonitoredValve> runtimeValvesMap = new java.util.LinkedHashMap<>();
		for (org.henbru.antidos.collector.model.MonitoredValve mv : runtimeValves) {
			runtimeValvesMap.put(mv.valveName(), mv);
			valveNames.add(mv.valveName());
		}

		List<org.henbru.antidos.collector.config.EffectiveValveRule> configuredValves = new ArrayList<>();
		for (String vName : valveNames) {
			configuredValves.add(valveRuleResolver.resolve(endpoint, vName));
		}
		configuredValves.sort((a, b) -> {
			org.henbru.antidos.collector.model.MonitoredValve ma = runtimeValvesMap.get(a.valveName());
			org.henbru.antidos.collector.model.MonitoredValve mb = runtimeValvesMap.get(b.valveName());
			boolean aActive = ma != null && ma.isActive();
			boolean bActive = mb != null && mb.isActive();
			if (aActive != bActive) {
				return aActive ? -1 : 1;
			}
			int orderA = ma != null ? ma.pipelineOrder() : 999;
			int orderB = mb != null ? mb.pipelineOrder() : 999;
			if (orderA != orderB) {
				return Integer.compare(orderA, orderB);
			}
			return a.valveName().compareToIgnoreCase(b.valveName());
		});

		List<org.henbru.antidos.collector.model.MonitoredValve> displayedRuntimeValves = runtimeValves;
		if (effectiveValve != null) {
			displayedRuntimeValves = runtimeValves.stream()
					.filter(mv -> mv.valveName().equalsIgnoreCase(effectiveValve))
					.toList();
		}
		displayedRuntimeValves = displayedRuntimeValves.stream()
				.sorted((a, b) -> {
					if (a.isActive() != b.isActive()) {
						return a.isActive() ? -1 : 1;
					}
					if (a.pipelineOrder() != b.pipelineOrder()) {
						return Integer.compare(a.pipelineOrder(), b.pipelineOrder());
					}
					return a.valveName().compareToIgnoreCase(b.valveName());
				})
				.toList();

		long activeValvesCount = runtimeValves.stream().filter(org.henbru.antidos.collector.model.MonitoredValve::isActive).count();
		long inactiveValvesCount = runtimeValves.size() - activeValvesCount;

		model.addAttribute("server", hb);
		model.addAttribute("serverId", serverId);
		model.addAttribute("endpointConfig", endpoint);
		model.addAttribute("configuredValves", configuredValves);
		model.addAttribute("runtimeValves", displayedRuntimeValves);
		model.addAttribute("runtimeValvesMap", runtimeValvesMap);
		model.addAttribute("activeValvesCount", activeValvesCount);
		model.addAttribute("inactiveValvesCount", inactiveValvesCount);
		model.addAttribute("selectedValve", effectiveValve);
		model.addAttribute("selectedStatus", effectiveStatus);
		model.addAttribute("recentSlots", recentSlots);
		model.addAttribute("recentEvents", recentEvents);
		model.addAttribute("slotEventsMap", slotEventsMap);
		return "server-details";
	}

	@PostMapping("/server/{serverId}/valves/{valveName}/delete")
	public String deleteValve(
			@PathVariable(name = "serverId") String serverId,
			@PathVariable(name = "valveName") String valveName,
			@RequestParam(name = "deleteHistory", required = false, defaultValue = "false") boolean deleteHistory,
			org.springframework.web.servlet.mvc.support.RedirectAttributes redirectAttributes) {

		int configsDeleted = (monitoredValveRepository != null)
				? monitoredValveRepository.deleteByServerIdAndValveName(serverId, valveName)
				: 0;

		int slotsDeleted = 0;
		int eventsDeleted = 0;
		if (deleteHistory) {
			if (slotSnapshotRepository != null) {
				slotsDeleted = slotSnapshotRepository.deleteByServerIdAndValveName(serverId, valveName);
			}
			if (clientEventRepository != null) {
				eventsDeleted = clientEventRepository.deleteByServerIdAndValveName(serverId, valveName);
			}
		}

		if (collectorPollerService != null) {
			collectorPollerService.forgetValveConfig(serverId, valveName);
		}

		if (deleteHistory) {
			redirectAttributes.addFlashAttribute("message",
					"Valve '" + valveName + "' permanently deleted (" + configsDeleted + " configuration, "
							+ slotsDeleted + " snapshots, " + eventsDeleted + " events removed).");
		} else {
			redirectAttributes.addFlashAttribute("message",
					"Valve configuration for '" + valveName + "' removed.");
		}
		return "redirect:/server/" + serverId;
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
		List<ClientEvent> recentEvents = clientEventRepository.findRecentBlockingEvents(null, null, 50);
		List<SlotSnapshot> recentSlots = slotSnapshotRepository.findRecentFleet(20);

		model.addAttribute("heartbeats", heartbeats);
		model.addAttribute("fleetSummary", buildFleetSummary(heartbeats));
		model.addAttribute("topOffenders", topOffenders);
		model.addAttribute("recentEvents", recentEvents);
		model.addAttribute("recentSlots", recentSlots);

		if (analyticsService != null) {
			org.henbru.antidos.collector.model.AnalyticsDashboardDto analytics =
					analyticsService.getDashboardAnalytics(24, null, null);
			model.addAttribute("analytics", analytics);
			model.addAttribute("analyticsJson", toJson(analytics));
		}
		model.addAttribute("selectedHours", 24);
		model.addAttribute("activeTab", "charts");
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
		String asOrgQuery = (parsedAsn == null && asnStr != null && !asnStr.isBlank()) ? asnStr.trim() : null;
		String normalizedStatus = (status != null && !status.isBlank() && !"ALL".equalsIgnoreCase(status.trim()))
				? status.trim().toUpperCase()
				: null;

		List<ClientEvent> events = clientEventRepository.findRecentEventsFiltered(
				servers, valves, fromTime, toTime, clientQuery, clientTypes, parsedAsn, asOrgQuery, normalizedStatus, limit, offset);
		long totalCount = clientEventRepository.countRecentEventsFiltered(
				servers, valves, fromTime, toTime, clientQuery, clientTypes, parsedAsn, asOrgQuery, normalizedStatus);

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
		model.addAttribute("minSurgeRequests", properties != null ? properties.getSurgeMinRequests() : 1000L);
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
			String activityPattern,
			Long minRequests,
			String sortBy,
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
		String asOrgQuery = (parsedAsn == null && asnStr != null && !asnStr.isBlank()) ? asnStr.trim() : null;
		String normalizedStatus = (status != null && !status.isBlank() && !"ALL".equalsIgnoreCase(status.trim()))
				? status.trim().toUpperCase()
				: null;

		boolean hasPatternFilter = activityPattern != null && !activityPattern.isBlank() && !"ALL".equalsIgnoreCase(activityPattern.trim());
		String effectiveGroupBy = "PROFILES".equalsIgnoreCase(groupBy) || "PROFILE".equalsIgnoreCase(groupBy) ? "PROFILES"
				: ("ROLLUP".equalsIgnoreCase(groupBy) ? "ROLLUP"
				: ("ASN".equalsIgnoreCase(groupBy) ? "ASN" : ("SUBNET".equalsIgnoreCase(groupBy) ? "SUBNET" : "CLIENT")));

		String effectiveSortBy = sortBy;
		if (effectiveSortBy == null || effectiveSortBy.isBlank()) {
			effectiveSortBy = "PROFILES".equals(effectiveGroupBy) ? "SURGE" : "BLOCKED";
		} else if ("PROFILES".equals(effectiveGroupBy) && "BLOCKED".equalsIgnoreCase(effectiveSortBy)) {
			effectiveSortBy = "SURGE";
		} else if (!"PROFILES".equals(effectiveGroupBy) && ("SURGE".equalsIgnoreCase(effectiveSortBy) || "DISTINCT_IPS".equalsIgnoreCase(effectiveSortBy) || "DORMANT".equalsIgnoreCase(effectiveSortBy))) {
			effectiveSortBy = "BLOCKED";
		}

		if (hasPatternFilter && "CLIENT".equals(effectiveGroupBy)) {
			effectiveGroupBy = "PROFILES";
		}

		switch (effectiveGroupBy) {
		case "PROFILES" -> {
			if (subnetProfileService != null && subnetProfileService.countProfilesFiltered("ALL", null, null, null, null, null) == 0) {
				try {
					subnetProfileService.refreshProfiles();
				} catch (Exception ignored) {
				}
			}

			List<org.henbru.antidos.collector.model.SubnetProfile> profiles = (subnetProfileService != null)
					? subnetProfileService.findProfilesFiltered(activityPattern, minRequests, clientQuery, parsedAsn, asOrgQuery, clientTypes, effectiveSortBy, limit, 0)
					: List.of();
			long totalProfiles = (subnetProfileService != null)
					? subnetProfileService.countProfilesFiltered(activityPattern, minRequests, clientQuery, parsedAsn, asOrgQuery, clientTypes)
					: 0L;
			model.addAttribute("subnetProfiles", profiles);
			model.addAttribute("totalProfiles", totalProfiles);
			model.addAttribute("subnetRollups", List.of());
			model.addAttribute("totalRollups", 0L);
			model.addAttribute("topOffenders", List.of());
			model.addAttribute("subnetProfilesMap", Map.of());
		}
		case "ROLLUP" -> {
			List<org.henbru.antidos.collector.model.ClientSubnetRollup> subnetRollups = subnetRollupRepository.findRollupsFiltered(
					servers, valves, fromTime, toTime, clientQuery, parsedAsn, asOrgQuery, clientTypes, limit, 0);
			long totalRollups = subnetRollupRepository.countRollupsFiltered(
					servers, valves, fromTime, toTime, clientQuery, parsedAsn, asOrgQuery, clientTypes);

			if (hasPatternFilter && subnetProfileService != null) {
				List<org.henbru.antidos.collector.model.SubnetProfile> matched = subnetProfileService.findProfilesFiltered(
						activityPattern, minRequests, null, parsedAsn, asOrgQuery, clientTypes, "SURGE", 1000, 0);
				Set<String> matchedSubnets = matched.stream().map(org.henbru.antidos.collector.model.SubnetProfile::subnetGroup).collect(Collectors.toSet());
				subnetRollups = subnetRollups.stream().filter(r -> matchedSubnets.contains(r.subnetGroup())).toList();
				totalRollups = subnetRollups.size();
			}

			List<String> subnets = subnetRollups.stream()
					.map(org.henbru.antidos.collector.model.ClientSubnetRollup::subnetGroup)
					.filter(Objects::nonNull)
					.distinct()
					.toList();
			Map<String, org.henbru.antidos.collector.model.SubnetProfile> profileMap = (subnetProfileService != null && !subnets.isEmpty())
					? subnetProfileService.findSubnetProfilesMap(subnets)
					: Map.of();

			model.addAttribute("subnetRollups", subnetRollups);
			model.addAttribute("totalRollups", totalRollups);
			model.addAttribute("subnetProfilesMap", profileMap);
			model.addAttribute("topOffenders", List.of());
			model.addAttribute("subnetProfiles", List.of());
			model.addAttribute("totalProfiles", 0L);
		}
		default -> {
			List<TopOffenderSummary> topOffenders = clientEventRepository.findTopOffendersFiltered(
					servers, valves, fromTime, toTime, clientQuery, clientTypes, parsedAsn, asOrgQuery, normalizedStatus, effectiveGroupBy, effectiveSortBy, limit);

			if (hasPatternFilter && "SUBNET".equals(effectiveGroupBy) && subnetProfileService != null) {
				List<org.henbru.antidos.collector.model.SubnetProfile> matched = subnetProfileService.findProfilesFiltered(
						activityPattern, minRequests, null, parsedAsn, asOrgQuery, clientTypes, "SURGE", 1000, 0);
				Set<String> matchedSubnets = matched.stream().map(org.henbru.antidos.collector.model.SubnetProfile::subnetGroup).collect(Collectors.toSet());
				topOffenders = topOffenders.stream().filter(o -> matchedSubnets.contains(o.clientKey())).toList();
			}

			List<String> subnets = topOffenders.stream()
					.map(TopOffenderSummary::clientKey)
					.filter(Objects::nonNull)
					.distinct()
					.toList();
			Map<String, org.henbru.antidos.collector.model.SubnetProfile> profileMap = (subnetProfileService != null && "SUBNET".equals(effectiveGroupBy) && !subnets.isEmpty())
					? subnetProfileService.findSubnetProfilesMap(subnets)
					: Map.of();

			model.addAttribute("topOffenders", topOffenders);
			model.addAttribute("subnetProfilesMap", profileMap);
			model.addAttribute("subnetRollups", List.of());
			model.addAttribute("totalRollups", 0L);
			model.addAttribute("subnetProfiles", List.of());
			model.addAttribute("totalProfiles", 0L);
		}
		}

		model.addAttribute("groupBy", effectiveGroupBy);
		model.addAttribute("activityPattern", activityPattern != null ? activityPattern : "ALL");
		model.addAttribute("minRequests", minRequests != null ? minRequests : 0L);
		model.addAttribute("sortBy", effectiveSortBy);
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
		model.addAttribute("minSurgeRequests", properties != null ? properties.getSurgeMinRequests() : 1000L);
	}

	private void populateProfilesModel(
			String activityPattern,
			Long minRequests,
			String clientQuery,
			String asnStr,
			List<String> clientTypes,
			String sortBy,
			int limit,
			int offset,
			Model model) {

		if (subnetProfileService != null && subnetProfileService.countProfilesFiltered("ALL", null, null, null, null, null) == 0) {
			try {
				subnetProfileService.refreshProfiles();
			} catch (Exception ignored) {
			}
		}

		Long parsedAsn = parseAsn(asnStr);
		String asOrgQuery = (parsedAsn == null && asnStr != null && !asnStr.isBlank()) ? asnStr.trim() : null;

		List<org.henbru.antidos.collector.model.SubnetProfile> profiles = (subnetProfileService != null)
				? subnetProfileService.findProfilesFiltered(activityPattern, minRequests, clientQuery, parsedAsn, asOrgQuery, clientTypes, sortBy, limit, offset)
				: List.of();
		long totalProfiles = (subnetProfileService != null)
				? subnetProfileService.countProfilesFiltered(activityPattern, minRequests, clientQuery, parsedAsn, asOrgQuery, clientTypes)
				: 0L;

		org.henbru.antidos.collector.model.SubnetProfileStats stats = (subnetProfileService != null)
				? subnetProfileService.getProfileStats()
				: org.henbru.antidos.collector.model.SubnetProfileStats.empty();

		boolean hasMore = (offset + profiles.size()) < totalProfiles;
		int nextOffset = offset + limit;

		org.henbru.antidos.collector.model.SubnetProfileFreshness freshness = (subnetProfileService != null)
				? subnetProfileService.getProfileFreshness()
				: null;

		model.addAttribute("subnetProfiles", profiles);
		model.addAttribute("totalProfiles", totalProfiles);
		model.addAttribute("profileStats", stats);
		model.addAttribute("freshness", freshness);
		model.addAttribute("activityPattern", activityPattern != null ? activityPattern : "ALL");
		model.addAttribute("minRequests", minRequests != null ? minRequests : 0L);
		model.addAttribute("clientQuery", clientQuery != null ? clientQuery : "");
		model.addAttribute("selectedAsn", asnStr != null ? asnStr : "");
		model.addAttribute("selectedTypes", clientTypes != null ? clientTypes : List.of());
		model.addAttribute("sortBy", sortBy != null ? sortBy : "SURGE");
		model.addAttribute("limit", limit);
		model.addAttribute("offset", offset);
		model.addAttribute("hasMore", hasMore);
		model.addAttribute("nextOffset", nextOffset);
		model.addAttribute("minSurgeRequests", properties != null ? properties.getSurgeMinRequests() : 1000L);
	}

	private String toJson(Object obj) {
		if (obj == null) return "{}";
		try {
			return objectMapper.writeValueAsString(obj);
		} catch (JsonProcessingException e) {
			return "{}";
		}
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
		long totalMarked = slotSnapshotRepository.sumMarkedRequestsSince(since24h);
		long distinctMarked = clientEventRepository.countDistinctMarkedClientsSince(since24h);

		return new FleetSummary(
				totalEndpoints,
				online,
				offline,
				totalValves,
				totalRequests,
				totalBlocked,
				distinctBlocked,
				totalMarked,
				distinctMarked
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
