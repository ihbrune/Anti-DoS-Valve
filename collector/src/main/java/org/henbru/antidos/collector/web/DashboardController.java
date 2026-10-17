package org.henbru.antidos.collector.web;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.FleetSummary;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controller serving the main Web UI and dynamic HTMX fragment partials.
 */
@Controller
public class DashboardController {

	private final HeartbeatRepository heartbeatRepository;
	private final SlotSnapshotRepository slotSnapshotRepository;
	private final ClientEventRepository clientEventRepository;

	public DashboardController(
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository) {
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
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

	@SuppressWarnings("null")
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
