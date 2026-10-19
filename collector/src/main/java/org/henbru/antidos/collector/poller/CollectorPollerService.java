package org.henbru.antidos.collector.poller;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import jakarta.annotation.PreDestroy;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service that orchestrates periodic polling, gap catch-up, and telemetry persistence for monitored endpoints.
 */
@Service
public class CollectorPollerService {

	private static final Logger log = LoggerFactory.getLogger(CollectorPollerService.class);

	private final CollectorProperties properties;
	private final ValveStatusClient statusClient;
	private final HeartbeatRepository heartbeatRepository;
	private final SlotSnapshotRepository slotSnapshotRepository;
	private final ClientEventRepository clientEventRepository;
	private final PollEventLogRepository pollEventLogRepository;
	private final ExecutorService pollerExecutor;

	@Autowired
	public CollectorPollerService(
			CollectorProperties properties,
			ValveStatusClient statusClient,
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository) {
		this(properties, statusClient, heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				Executors.newVirtualThreadPerTaskExecutor());
	}

	CollectorPollerService(
			CollectorProperties properties,
			ValveStatusClient statusClient,
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			ExecutorService pollerExecutor) {
		this.properties = properties;
		this.statusClient = statusClient;
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.pollEventLogRepository = pollEventLogRepository;
		this.pollerExecutor = pollerExecutor != null ? pollerExecutor : Executors.newVirtualThreadPerTaskExecutor();
	}

	@PreDestroy
	public void shutdown() {
		if (pollerExecutor != null && !pollerExecutor.isShutdown()) {
			pollerExecutor.shutdown();
		}
	}

	public void pollFleet() {
		List<EndpointConfig> enabledEndpoints = properties.getEndpoints().stream()
				.filter(endpoint -> endpoint != null && endpoint.isEnabled())
				.toList();

		if (enabledEndpoints.isEmpty()) {
			log.debug("No endpoints configured for polling.");
			return;
		}

		if (enabledEndpoints.size() == 1 || !properties.isParallelFleetPolling()) {
			for (EndpointConfig endpoint : enabledEndpoints) {
				pollEndpoint(endpoint);
			}
			return;
		}

		// Parallel polling across different servers using Java 21 Virtual Threads.
		// Requests to valves on the same host remain strictly sequential.
		List<CompletableFuture<Void>> futures = new ArrayList<>(enabledEndpoints.size());
		for (EndpointConfig endpoint : enabledEndpoints) {
			futures.add(CompletableFuture.runAsync(() -> {
				try {
					pollEndpoint(endpoint);
				} catch (Throwable t) {
					log.error("Unexpected error in parallel poll for endpoint '{}': {}", endpoint.getName(), t.getMessage(), t);
				}
			}, pollerExecutor));
		}

		CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
	}

	public void pollEndpoint(EndpointConfig endpoint) {
		long start = System.currentTimeMillis();
		Instant now = Instant.now();
		int valvesPolled = 0;
		int slotsIngested = 0;
		int eventsIngested = 0;
		List<String> warnings = new ArrayList<>();

		try {
			ValveOverviewDto overview = statusClient.fetchOverview(endpoint);
			long duration = System.currentTimeMillis() - start;

			int valveCount = overview.valves() != null
					? (int) overview.valves().stream().filter(v -> endpoint.isValveIncluded(v.monitorName())).count()
					: 0;
			heartbeatRepository.upsert(new EndpointHeartbeat(
					endpoint.getName(),
					endpoint.getUrl(),
					true,
					now,
					now,
					null,
					duration,
					valveCount
			));

			if (overview.valves() != null && !overview.valves().isEmpty()) {
				for (ValveOverviewDto.ValveSummaryDto v : overview.valves()) {
					if (!endpoint.isValveIncluded(v.monitorName())) {
						log.debug("Skipping valve '{}' on '{}' (excluded by endpoint configuration)", v.monitorName(), endpoint.getName());
						continue;
					}
					valvesPolled++;
					IngestResult result = ingestValve(endpoint, v, now);
					slotsIngested += result.slotsIngested();
					eventsIngested += result.eventsIngested();
					warnings.addAll(result.warnings());
				}
			}

			long totalDuration = System.currentTimeMillis() - start;
			String status = "SUCCESS";
			String details = "Polled " + valvesPolled + " valve(s), " + slotsIngested + " slot(s), " + eventsIngested + " event(s)";
			String errorMsg = null;

			if (!warnings.isEmpty()) {
				status = "WARNING";
				details = "Partial success (" + warnings.size() + " issue(s)): " + String.join("; ", warnings);
				errorMsg = String.join("; ", warnings);
			} else if (totalDuration > properties.getSlowPollThresholdMs()) {
				status = "WARNING";
				details = "Slow response: " + totalDuration + " ms (threshold: " + properties.getSlowPollThresholdMs() + " ms)";
			}

			pollEventLogRepository.insert(new PollEventLog(
					null,
					endpoint.getName(),
					endpoint.getUrl(),
					now,
					status,
					200,
					totalDuration,
					valvesPolled,
					slotsIngested,
					eventsIngested,
					details,
					errorMsg
			));

		} catch (IOException | InterruptedException | RuntimeException e) {
			long duration = System.currentTimeMillis() - start;
			String errorMsg = ValveStatusClient.formatErrorMessage(e);
			log.warn("Failed to poll endpoint '{}' ({}): {}", endpoint.getName(), endpoint.getUrl(), errorMsg);
			heartbeatRepository.upsert(new EndpointHeartbeat(
					endpoint.getName(),
					endpoint.getUrl(),
					false,
					now,
					null,
					errorMsg,
					duration,
					0
			));

			int httpStatus = extractStatusCode(e);
			pollEventLogRepository.insert(new PollEventLog(
					null,
					endpoint.getName(),
					endpoint.getUrl(),
					now,
					"ERROR",
					httpStatus,
					duration,
					0,
					0,
					0,
					"Connection failed: " + errorMsg,
					errorMsg
			));
		}
	}

	private IngestResult ingestValve(EndpointConfig endpoint, ValveOverviewDto.ValveSummaryDto summary, Instant pollTime) {
		String valveName = summary.monitorName();
		long lastCompletedKey = summary.lastCompletedSlotKey();
		int slots = 0;
		int events = 0;
		List<String> warnings = new ArrayList<>();

		// 1. Check for missed slots (catch-up recovery)
		Optional<Long> latestCompletedKey = slotSnapshotRepository.findLatestCompletedSlotKey(endpoint.getName(), valveName);
		if (latestCompletedKey.isPresent() && lastCompletedKey > 0) {
			long lastStored = latestCompletedKey.get();
			int ringBufferCapacity = summary.numberOfSlots() > 0 ? summary.numberOfSlots() : 5;
			long earliestRetrievableKey = Math.max(0, summary.currentSlotKey() - ringBufferCapacity);

			long catchUpStart = Math.max(lastStored + 1, earliestRetrievableKey);
			for (long k = catchUpStart; k < lastCompletedKey; k++) {
				SlotIngestResult r = fetchAndStoreSlot(endpoint, valveName, String.valueOf(k), true, pollTime);
				slots += r.slotsCount();
				events += r.eventsCount();
				if (r.warning() != null) {
					warnings.add(r.warning());
				}
			}
		}

		// 2. Poll the finalized previous slot (normal flow)
		// Completed slots are immutable; only fetch if this finalized slot has not been ingested yet
		if (lastCompletedKey > 0 && (latestCompletedKey.isEmpty() || latestCompletedKey.get() < lastCompletedKey)) {
			SlotIngestResult r = fetchAndStoreSlot(endpoint, valveName, "previous", true, pollTime);
			slots += r.slotsCount();
			events += r.eventsCount();
			if (r.warning() != null) {
				warnings.add(r.warning());
			}
		}

		// 3. Optional: Poll intermediate snapshot of current in-progress slot
		if (endpoint.isPollIntermediateSlots()) {
			SlotIngestResult r = fetchAndStoreSlot(endpoint, valveName, "current", false, pollTime);
			slots += r.slotsCount();
			events += r.eventsCount();
			if (r.warning() != null) {
				warnings.add(r.warning());
			}
		}

		return new IngestResult(slots, events, warnings);
	}

	private SlotIngestResult fetchAndStoreSlot(EndpointConfig endpoint, String valveName, String slotParam, boolean completed, Instant pollTime) {
		try {
			// Request blockedLimit=all and activeLimit=0 to avoid serialization overhead for non-blocked clients on the Valve.
			// limit=all is retained as backward-compatible fallback for older Valve versions.
			ValveDetailsDto details = statusClient.fetchSlotDetails(endpoint, valveName, slotParam, "all", "all", "0");
			if (details.selectedSlot() == null) {
				return new SlotIngestResult(0, 0, null);
			}

			ValveDetailsDto.SelectedSlotDto slot = details.selectedSlot();
			Instant start = parseInstantOrFallback(slot.startTime(), pollTime);
			Instant end = parseInstantOrFallback(slot.endTime(), pollTime);

			SlotSnapshot snapshot = new SlotSnapshot(
					null,
					endpoint.getName(),
					valveName,
					slot.slotKey(),
					start,
					end,
					slot.totalRequests(),
					slot.activeCounters(),
					slot.blockedCounters(),
					completed,
					pollTime
			);
			slotSnapshotRepository.upsert(snapshot);

			int eventsCount = 0;
			if (details.blockedClients() != null && !details.blockedClients().isEmpty()) {
				List<BlockedClientEvent> events = new ArrayList<>();
				for (ValveDetailsDto.BlockedClientDto c : details.blockedClients()) {
					events.add(new BlockedClientEvent(
							null,
							endpoint.getName(),
							valveName,
							slot.slotKey(),
							start,
							c.key(),
							c.count(),
							c.retained(),
							c.locked(),
							completed,
							pollTime
					));
				}
				clientEventRepository.batchUpsert(events);
				eventsCount = events.size();
			}

			return new SlotIngestResult(1, eventsCount, null);

		} catch (IOException | InterruptedException | RuntimeException e) {
			String err = "Valve '" + valveName + "' slot '" + slotParam + "' failed: " + ValveStatusClient.formatErrorMessage(e);
			log.warn("Could not fetch slot '{}' for valve '{}' on '{}': {}",
					slotParam, valveName, endpoint.getName(), ValveStatusClient.formatErrorMessage(e));
			return new SlotIngestResult(0, 0, err);
		}
	}

	private static int extractStatusCode(Throwable t) {
		if (t == null) {
			return 0;
		}
		String msg = t.getMessage();
		if (msg != null && msg.startsWith("HTTP ")) {
			try {
				int end = msg.indexOf(' ', 5);
				String codeStr = end > 5 ? msg.substring(5, end) : msg.substring(5, Math.min(msg.length(), 8));
				return Integer.parseInt(codeStr.trim());
			} catch (NumberFormatException ignored) {
			}
		}
		return 0;
	}

	private record SlotIngestResult(int slotsCount, int eventsCount, String warning) {}
	private record IngestResult(int slotsIngested, int eventsIngested, List<String> warnings) {}

	private static Instant parseInstantOrFallback(String str, Instant fallback) {
		if (str == null || str.trim().isEmpty()) {
			return fallback;
		}
		try {
			return Instant.parse(str.trim());
		} catch (DateTimeParseException e) {
			return fallback;
		}
	}
}
