package org.henbru.antidos.collector.poller;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

	public CollectorPollerService(
			CollectorProperties properties,
			ValveStatusClient statusClient,
			HeartbeatRepository heartbeatRepository,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository) {
		this.properties = properties;
		this.statusClient = statusClient;
		this.heartbeatRepository = heartbeatRepository;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
	}

	public void pollFleet() {
		List<EndpointConfig> endpoints = properties.getEndpoints();
		if (endpoints.isEmpty()) {
			log.debug("No endpoints configured for polling.");
			return;
		}

		for (EndpointConfig endpoint : endpoints) {
			if (!endpoint.isEnabled()) {
				continue;
			}
			pollEndpoint(endpoint);
		}
	}

	public void pollEndpoint(EndpointConfig endpoint) {
		long start = System.currentTimeMillis();
		Instant now = Instant.now();
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

			if (overview.valves() == null || overview.valves().isEmpty()) {
				return;
			}

			for (ValveOverviewDto.ValveSummaryDto v : overview.valves()) {
				if (!endpoint.isValveIncluded(v.monitorName())) {
					log.debug("Skipping valve '{}' on '{}' (excluded by endpoint configuration)", v.monitorName(), endpoint.getName());
					continue;
				}
				ingestValve(endpoint, v, now);
			}

		} catch (java.io.IOException | InterruptedException | RuntimeException e) {
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
		}
	}

	private void ingestValve(EndpointConfig endpoint, ValveOverviewDto.ValveSummaryDto summary, Instant pollTime) {
		String valveName = summary.monitorName();
		long lastCompletedKey = summary.lastCompletedSlotKey();

		// 1. Check for missed slots (catch-up recovery)
		Optional<Long> latestKnownKey = slotSnapshotRepository.findLatestSlotKey(endpoint.getName(), valveName);
		if (latestKnownKey.isPresent() && lastCompletedKey > 0) {
			long lastStored = latestKnownKey.get();
			int ringBufferCapacity = summary.numberOfSlots() > 0 ? summary.numberOfSlots() : 5;
			long earliestRetrievableKey = Math.max(0, summary.currentSlotKey() - ringBufferCapacity);

			long catchUpStart = Math.max(lastStored + 1, earliestRetrievableKey);
			for (long k = catchUpStart; k < lastCompletedKey; k++) {
				fetchAndStoreSlot(endpoint, valveName, String.valueOf(k), true, pollTime);
			}
		}

		// 2. Poll the finalized previous slot (normal flow)
		if (lastCompletedKey > 0) {
			fetchAndStoreSlot(endpoint, valveName, "previous", true, pollTime);
		}

		// 3. Optional: Poll intermediate snapshot of current in-progress slot
		if (endpoint.isPollIntermediateSlots()) {
			fetchAndStoreSlot(endpoint, valveName, "current", false, pollTime);
		}
	}

	private void fetchAndStoreSlot(EndpointConfig endpoint, String valveName, String slotParam, boolean completed, Instant pollTime) {
		try {
			ValveDetailsDto details = statusClient.fetchSlotDetails(endpoint, valveName, slotParam, "all");
			if (details.selectedSlot() == null) {
				return;
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
			}

		} catch (java.io.IOException | InterruptedException | RuntimeException e) {
			log.warn("Could not fetch slot '{}' for valve '{}' on '{}': {}",
					slotParam, valveName, endpoint.getName(), ValveStatusClient.formatErrorMessage(e));
		}
	}

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
