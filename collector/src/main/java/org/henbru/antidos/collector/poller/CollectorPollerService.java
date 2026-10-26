package org.henbru.antidos.collector.poller;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.config.ValveRuleResolver;
import org.henbru.antidos.collector.enrichment.EntityResolver;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.NetworkEntity;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.annotation.PreDestroy;

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
	private final org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository;
	private final EntityResolver entityResolver;
	private final ValveRuleResolver valveRuleResolver;
	private final ExecutorService pollerExecutor;

	private final java.util.concurrent.ConcurrentMap<String, Integer> knownConfigHashes = new java.util.concurrent.ConcurrentHashMap<>();

	@Autowired
	public CollectorPollerService(
			CollectorProperties properties,
			ValveStatusClient statusClient,
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository,
			EntityResolver entityResolver,
			ValveRuleResolver valveRuleResolver) {
		this(properties, statusClient, heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				monitoredValveRepository, entityResolver, valveRuleResolver, Executors.newVirtualThreadPerTaskExecutor());
	}

	public CollectorPollerService(
			CollectorProperties properties,
			ValveStatusClient statusClient,
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			EntityResolver entityResolver,
			ValveRuleResolver valveRuleResolver) {
		this(properties, statusClient, heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				null, entityResolver, valveRuleResolver, Executors.newVirtualThreadPerTaskExecutor());
	}

	public CollectorPollerService(
			CollectorProperties properties,
			ValveStatusClient statusClient,
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			EntityResolver entityResolver,
			ExecutorService pollerExecutor) {
		this(properties, statusClient, heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				null, entityResolver, new ValveRuleResolver(properties), pollerExecutor);
	}

	public CollectorPollerService(
			CollectorProperties properties,
			ValveStatusClient statusClient,
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository,
			EntityResolver entityResolver,
			ValveRuleResolver valveRuleResolver,
			ExecutorService pollerExecutor) {
		this.properties = properties;
		this.statusClient = statusClient;
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.pollEventLogRepository = pollEventLogRepository;
		this.monitoredValveRepository = monitoredValveRepository;
		this.entityResolver = entityResolver;
		this.valveRuleResolver = valveRuleResolver != null ? valveRuleResolver : new ValveRuleResolver(properties);
		this.pollerExecutor = pollerExecutor != null ? pollerExecutor : Executors.newVirtualThreadPerTaskExecutor();
	}

	public CollectorPollerService(
			CollectorProperties properties,
			ValveStatusClient statusClient,
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			PollEventLogRepository pollEventLogRepository) {
		this(properties, statusClient, heartbeatRepository, slotSnapshotRepository, clientEventRepository, pollEventLogRepository,
				null, null, new ValveRuleResolver(properties), Executors.newVirtualThreadPerTaskExecutor());
	}

	@PreDestroy
	public void shutdown() {
		if (pollerExecutor != null && !pollerExecutor.isShutdown()) {
			pollerExecutor.shutdown();
		}
	}

	private volatile Instant lastFleetPollTime;

	public Instant getLastFleetPollTime() {
		return lastFleetPollTime;
	}

	public void pollFleet() {
		this.lastFleetPollTime = Instant.now();
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
		int blockedEventsIngested = 0;
		long totalNetworkMs = 0;
		List<String> warnings = new ArrayList<>();

		try {
			long overviewStart = System.currentTimeMillis();
			ValveOverviewDto overview = statusClient.fetchOverview(endpoint);
			long overviewDuration = System.currentTimeMillis() - overviewStart;
			totalNetworkMs += overviewDuration;

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
					overviewDuration,
					valveCount
			));

			if (overview.valves() != null && !overview.valves().isEmpty()) {
				for (ValveOverviewDto.ValveSummaryDto v : overview.valves()) {
					if (!endpoint.isValveIncluded(v.monitorName())) {
						log.debug("Skipping valve '{}' on '{}' (excluded by endpoint configuration)", v.monitorName(), endpoint.getName());
						continue;
					}
					valvesPolled++;
					updateValveConfigIfChanged(endpoint.getName(), v, now);
					IngestResult result = ingestValve(endpoint, v, now);
					slotsIngested += result.slotsIngested();
					eventsIngested += result.eventsIngested();
					blockedEventsIngested += result.blockedEventsIngested();
					warnings.addAll(result.warnings());
					totalNetworkMs += result.networkDurationMs();
				}
			}

			long totalDuration = System.currentTimeMillis() - start;
			long dbDuration = Math.max(0, totalDuration - totalNetworkMs);
			String status = "SUCCESS";
			int activeEventsIngested = Math.max(0, eventsIngested - blockedEventsIngested);
			String eventsBreakdown = blockedEventsIngested > 0
					? eventsIngested + " event(s) (" + blockedEventsIngested + " blocked, " + activeEventsIngested + " active)"
					: eventsIngested + " event(s)";
			String details = "Polled " + valvesPolled + " valve(s), " + slotsIngested + " slot(s), " + eventsBreakdown
					+ " in " + totalDuration + " ms (network: " + totalNetworkMs + " ms, db: " + dbDuration + " ms)";
			String errorMsg = null;

			if (!warnings.isEmpty()) {
				status = "WARNING";
				details = "Partial success (" + warnings.size() + " issue(s)): " + String.join("; ", warnings)
						+ " (network: " + totalNetworkMs + " ms, db: " + dbDuration + " ms)";
				errorMsg = String.join("; ", warnings);
			} else if (totalNetworkMs > properties.getSlowPollThresholdMs()) {
				status = "WARNING";
				details = "Slow endpoint response: " + totalNetworkMs + " ms (threshold: " + properties.getSlowPollThresholdMs() + " ms)";
			}

			pollEventLogRepository.insert(new PollEventLog(
					null,
					endpoint.getName(),
					endpoint.getUrl(),
					now,
					status,
					200,
					totalNetworkMs,
					valvesPolled,
					slotsIngested,
					eventsIngested,
					blockedEventsIngested,
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
		int blockedEvents = 0;
		long networkMs = 0;
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
				blockedEvents += r.blockedEventsCount();
				networkMs += r.networkDurationMs();
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
			blockedEvents += r.blockedEventsCount();
			networkMs += r.networkDurationMs();
			if (r.warning() != null) {
				warnings.add(r.warning());
			}
		}

		// 3. Optional: Poll intermediate snapshot of current in-progress slot
		if (endpoint.isPollIntermediateSlots()) {
			SlotIngestResult r = fetchAndStoreSlot(endpoint, valveName, "current", false, pollTime);
			slots += r.slotsCount();
			events += r.eventsCount();
			blockedEvents += r.blockedEventsCount();
			networkMs += r.networkDurationMs();
			if (r.warning() != null) {
				warnings.add(r.warning());
			}
		}

		return new IngestResult(slots, events, blockedEvents, warnings, networkMs);
	}

	private SlotIngestResult fetchAndStoreSlot(EndpointConfig endpoint, String valveName, String slotParam, boolean completed, Instant pollTime) {
		long netStart = System.currentTimeMillis();
		try {
			// Apply effective telemetry rules (activeLimit=0 if disabled, or activeLimit + activeMinCount)
			org.henbru.antidos.collector.config.EffectiveValveRule rule = valveRuleResolver.resolve(endpoint, valveName);
			String activeLimitParam = rule.collectActive() ? rule.activeLimit() : "0";
			Integer activeMinCountParam = rule.collectActive() ? rule.activeMinCount() : null;

			ValveDetailsDto details = (activeMinCountParam != null)
					? statusClient.fetchSlotDetails(endpoint, valveName, slotParam, "all", "all", activeLimitParam, null, null, activeMinCountParam)
					: statusClient.fetchSlotDetails(endpoint, valveName, slotParam, "all", "all", activeLimitParam);
			long netDuration = System.currentTimeMillis() - netStart;
			if (details.selectedSlot() == null) {
				return new SlotIngestResult(0, 0, 0, null, netDuration);
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
			int blockedCount = 0;
			List<ClientEvent> events = new ArrayList<>();

			boolean isVisitorTrackingActive = (details.valve() != null && Boolean.TRUE.equals(details.valve().visitorCookieEnabled()))
					|| (monitoredValveRepository != null && monitoredValveRepository.findByServerIdAndValveName(endpoint.getName(), valveName)
							.map(v -> v.visitorCookieEnabled())
							.orElse(false));

			// 1. Ingest blocked clients (status = BLOCKED, locked = true)
			if (details.blockedClients() != null && !details.blockedClients().isEmpty()) {
				blockedCount = details.blockedClients().size();
				for (ValveDetailsDto.BlockedClientDto c : details.blockedClients()) {
					Long entityId = null;
					if (entityResolver != null) {
						entityId = entityResolver.getCached(c.key())
								.map(entity -> entity.id())
								.orElse(null);
						if (entityId == null) {
							try {
								NetworkEntity entity = entityResolver.getOrCreate(c.key(), start);
								entityId = entity.id();
							} catch (Exception e) {
								log.debug("Could not resolve entity for key {}: {}", c.key(), e.getMessage());
							}
						}
					}
					Integer dc = c.distinctClients();
					int distinct = dc != null && dc > 0 ? dc : 1;
					Integer returning = (isVisitorTrackingActive && c.returningCount() != null) ? c.returningCount() : null;
					Integer authenticated = c.authenticatedCount();
					events.add(new ClientEvent(
							null,
							endpoint.getName(),
							valveName,
							slot.slotKey(),
							start,
							c.key(),
							c.count(),
							c.retained(),
							c.locked(),
							ClientEvent.STATUS_BLOCKED,
							completed,
							pollTime,
							distinct,
							returning,
							authenticated
					).withEntityId(entityId));
				}
			}

			// 2. Ingest active clients (status = ACTIVE, locked = false)
			// Uses memory-cached entity lookup to avoid synchronous DB write storms during parallel polling;
			// uncached entities are enriched asynchronously by BackgroundEnrichmentWorker.
			if (details.topActiveClients() != null && !details.topActiveClients().isEmpty()) {
				for (ValveDetailsDto.ActiveClientDto c : details.topActiveClients()) {
					Long entityId = null;
					if (entityResolver != null) {
						entityId = entityResolver.getCached(c.key())
								.map(entity -> entity.id())
								.orElse(null);
					}
					Integer dc = c.distinctClients();
					int distinct = dc != null && dc > 0 ? dc : 1;
					Integer returning = (isVisitorTrackingActive && c.returningCount() != null) ? c.returningCount() : null;
					Integer authenticated = c.authenticatedCount();
					events.add(new ClientEvent(
							null,
							endpoint.getName(),
							valveName,
							slot.slotKey(),
							start,
							c.key(),
							c.count(),
							c.retained(),
							false,
							ClientEvent.STATUS_ACTIVE,
							completed,
							pollTime,
							distinct,
							returning,
							authenticated
					).withEntityId(entityId));
				}
			}

			if (!events.isEmpty()) {
				clientEventRepository.batchUpsert(events);
				eventsCount = events.size();
			}

			return new SlotIngestResult(1, eventsCount, blockedCount, null, netDuration);

		} catch (IOException | InterruptedException | RuntimeException e) {
			long netDuration = System.currentTimeMillis() - netStart;
			String err = "Valve '" + valveName + "' slot '" + slotParam + "' failed: " + ValveStatusClient.formatErrorMessage(e);
			log.warn("Could not fetch slot '{}' for valve '{}' on '{}': {}",
					slotParam, valveName, endpoint.getName(), ValveStatusClient.formatErrorMessage(e));
			return new SlotIngestResult(0, 0, 0, err, netDuration);
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

	private void updateValveConfigIfChanged(String serverId, ValveOverviewDto.ValveSummaryDto v, Instant now) {
		if (monitoredValveRepository == null) {
			return;
		}
		String key = serverId + "#" + v.monitorName();
		int currentHash = v.configHashCode();
		Integer previousHash = knownConfigHashes.get(key);
		if (previousHash == null || previousHash != currentHash) {
			monitoredValveRepository.upsert(toMonitoredValve(serverId, v, now, currentHash));
			knownConfigHashes.put(key, currentHash);
			log.info("Ingested updated valve configuration for '{}/{}' (configHash: {})", serverId, v.monitorName(), currentHash);
		}
	}

	private org.henbru.antidos.collector.model.MonitoredValve toMonitoredValve(
			String serverId, ValveOverviewDto.ValveSummaryDto v, Instant now, int configHash) {
		return new org.henbru.antidos.collector.model.MonitoredValve(
				serverId,
				v.monitorName(),
				v.description(),
				v.pipelineOrder(),
				v.monitorMode() != null ? v.monitorMode() : "BLOCKING",
				v.simulationMode(),
				v.serverWideBlocking(),
				v.httpStatusCode() > 0 ? v.httpStatusCode() : 429,
				v.allowedRequestsPerSlot(),
				v.slotLength(),
				v.numberOfSlots(),
				v.shareOfRetainedFormerRequests(),
				v.ipv4SubnetMask() > 0 ? v.ipv4SubnetMask() : 32,
				v.ipv6SubnetMask() > 0 ? v.ipv6SubnetMask() : 64,
				v.maxIPCacheSize() > 0 ? v.maxIPCacheSize() : 10000,
				v.maxBlockedIPCacheSize() > 0 ? v.maxBlockedIPCacheSize() : 10000,
				v.relevantPaths(),
				v.nonRelevantPaths(),
				v.alwaysAllowedIPs(),
				v.alwaysForbiddenIPs(),
				v.statusUri(),
				v.statusAllowedIPs(),
				v.collectorIntegration() != null && !v.collectorIntegration().isBlank() ? v.collectorIntegration() : "auto",
				v.visitorCookieEnabled(),
				v.visitorCookieName() != null && !v.visitorCookieName().isBlank() ? v.visitorCookieName() : "_adv",
				now,
				configHash
		);
	}

	public void clearConfigHashes() {
		this.knownConfigHashes.clear();
	}

	private record SlotIngestResult(int slotsCount, int eventsCount, int blockedEventsCount, String warning, long networkDurationMs) {}
	private record IngestResult(int slotsIngested, int eventsIngested, int blockedEventsIngested, List<String> warnings, long networkDurationMs) {}

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
