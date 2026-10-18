package org.henbru.antidos.collector.demo;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.springframework.stereotype.Component;

/**
 * Deterministic telemetry simulation engine generating realistic AntiDoSValve payloads
 * for demo nodes (Edge EU, API Gateway US, Staging Node).
 */
@Component
public class MockValveSimulator {

	public static final int SLOT_LENGTH_SECONDS = 10;
	public static final int SLOT_LENGTH_MILLIS = SLOT_LENGTH_SECONDS * 1000;
	public static final int NUMBER_OF_SLOTS = 6;

	// IP pool for the simulated distributed attack on API Gateway
	private static final String[] ATTACKER_IPS = {
			"45.154.255.12", "185.220.101.5", "194.26.29.110", "91.240.118.77",
			"185.246.221.84", "103.149.28.19", "193.106.191.66", "195.123.245.9",
			"178.62.204.14", "167.99.165.88", "146.190.112.51", "159.65.130.22",
			"89.248.163.74", "194.38.20.141", "45.148.10.66", "193.32.162.201"
	};

	public ValveOverviewDto buildOverview(String nodeId, String filterValve) {
		long now = System.currentTimeMillis();
		long currentSlotKey = now / SLOT_LENGTH_MILLIS;
		long lastCompletedSlotKey = currentSlotKey - 1;
		String serverTime = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(now));

		List<ValveOverviewDto.ValveSummaryDto> valves = new ArrayList<>();

		String normalizedNode = normalizeNodeId(nodeId);
		switch (normalizedNode) {
			case "edge-eu" -> {
				if (matchesFilter(filterValve, "Primary-Rate-Limiter")) {
					valves.add(buildEdgePrimarySummary(currentSlotKey, lastCompletedSlotKey, 1));
				}
				if (matchesFilter(filterValve, "Subnet-Guard")) {
					valves.add(buildEdgeSubnetSummary(currentSlotKey, lastCompletedSlotKey, 2));
				}
			}
			case "api-gateway" -> {
				if (matchesFilter(filterValve, "API-DoS-Shield")) {
					valves.add(buildApiShieldSummary(currentSlotKey, lastCompletedSlotKey, 1));
				}
			}
			case "staging-node" -> {
				if (matchesFilter(filterValve, "Staging-Limiter")) {
					valves.add(buildStagingSummary(currentSlotKey, lastCompletedSlotKey, 1));
				}
			}
			default -> {
				valves.add(buildDefaultSummary("Generic-Limiter", currentSlotKey, lastCompletedSlotKey, 1));
			}
		}

		return new ValveOverviewDto(serverTime, valves, null);
	}

	public ValveDetailsDto buildDetails(String nodeId, String valveName, String slotParam, String limitParam) {
		long now = System.currentTimeMillis();
		long currentSlotKey = now / SLOT_LENGTH_MILLIS;
		long lastCompletedSlotKey = currentSlotKey - 1;
		String serverTime = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(now));

		String resolvedValve = resolveValveName(nodeId, valveName);
		ValveDetailsDto.ValveHeaderDto header = new ValveDetailsDto.ValveHeaderDto(
				resolvedValve,
				currentSlotKey,
				lastCompletedSlotKey,
				SLOT_LENGTH_MILLIS,
				NUMBER_OF_SLOTS
		);

		long targetSlotKey = resolveSlotKey(slotParam, currentSlotKey, lastCompletedSlotKey);
		boolean isCurrent = (targetSlotKey == currentSlotKey);
		String slotType = isCurrent ? "current" : (targetSlotKey == lastCompletedSlotKey ? "previous" : "historical");

		// Check if slot has expired from ring buffer
		if (targetSlotKey < currentSlotKey - NUMBER_OF_SLOTS || targetSlotKey > currentSlotKey) {
			return new ValveDetailsDto(serverTime, header, null, 0, "all", List.of(), "Slot not in ring buffer");
		}

		String startTime = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(targetSlotKey * SLOT_LENGTH_MILLIS));
		String endTime = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli((targetSlotKey + 1) * SLOT_LENGTH_MILLIS));

		SlotMetrics metrics = calculateMetrics(nodeId, resolvedValve, targetSlotKey);

		ValveDetailsDto.SelectedSlotDto selectedSlot = new ValveDetailsDto.SelectedSlotDto(
				slotType,
				(int) (targetSlotKey % NUMBER_OF_SLOTS),
				targetSlotKey,
				isCurrent,
				startTime,
				endTime,
				metrics.totalRequests(),
				metrics.activeCounters(),
				metrics.blockedCounters()
		);

		return new ValveDetailsDto(
				serverTime,
				header,
				selectedSlot,
				metrics.blockedClients().size(),
				"all",
				metrics.blockedClients(),
				null
		);
	}

	private String normalizeNodeId(String nodeId) {
		if (nodeId == null) {
			return "edge-eu";
		}
		String lower = nodeId.toLowerCase().trim();
		if (lower.contains("edge")) return "edge-eu";
		if (lower.contains("api")) return "api-gateway";
		if (lower.contains("staging")) return "staging-node";
		return lower;
	}

	private boolean matchesFilter(String filterValve, String candidate) {
		return filterValve == null || filterValve.isBlank() || filterValve.equalsIgnoreCase(candidate);
	}

	private String resolveValveName(String nodeId, String requestedValve) {
		if (requestedValve != null && !requestedValve.isBlank()) {
			return requestedValve.trim();
		}
		String norm = normalizeNodeId(nodeId);
		return switch (norm) {
			case "edge-eu" -> "Primary-Rate-Limiter";
			case "api-gateway" -> "API-DoS-Shield";
			case "staging-node" -> "Staging-Limiter";
			default -> "Default-Rate-Limiter";
		};
	}

	private long resolveSlotKey(String slotParam, long currentKey, long lastCompletedKey) {
		if (slotParam == null || slotParam.isBlank() || "current".equalsIgnoreCase(slotParam.trim())) {
			return currentKey;
		}
		if ("previous".equalsIgnoreCase(slotParam.trim())) {
			return lastCompletedKey;
		}
		try {
			return Long.parseLong(slotParam.trim());
		} catch (NumberFormatException e) {
			return lastCompletedKey;
		}
	}

	// -------------------------------------------------------------------------
	// Overview Summaries
	// -------------------------------------------------------------------------

	private ValveOverviewDto.ValveSummaryDto buildEdgePrimarySummary(long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics("edge-eu", "Primary-Rate-Limiter", currentKey);
		SlotMetrics prev = calculateMetrics("edge-eu", "Primary-Rate-Limiter", lastCompletedKey);

		long cumulative = 240_000L + (currentKey % 50_000L) * 1100L;
		return new ValveOverviewDto.ValveSummaryDto(
				"Primary-Rate-Limiter",
				order,
				"BLOCKING",
				false,
				false,
				120,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters()
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildEdgeSubnetSummary(long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics("edge-eu", "Subnet-Guard", currentKey);
		SlotMetrics prev = calculateMetrics("edge-eu", "Subnet-Guard", lastCompletedKey);

		long cumulative = 310_000L + (currentKey % 50_000L) * 1400L;
		return new ValveOverviewDto.ValveSummaryDto(
				"Subnet-Guard",
				order,
				"SIMULATION",
				true,
				false,
				350,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters()
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildApiShieldSummary(long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics("api-gateway", "API-DoS-Shield", currentKey);
		SlotMetrics prev = calculateMetrics("api-gateway", "API-DoS-Shield", lastCompletedKey);

		long cumulative = 1_850_000L + (currentKey % 50_000L) * 5200L;
		return new ValveOverviewDto.ValveSummaryDto(
				"API-DoS-Shield",
				order,
				"BLOCKING",
				false,
				true,
				60,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters()
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildStagingSummary(long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics("staging-node", "Staging-Limiter", currentKey);
		SlotMetrics prev = calculateMetrics("staging-node", "Staging-Limiter", lastCompletedKey);

		long cumulative = 45_000L + (currentKey % 50_000L) * 85L;
		return new ValveOverviewDto.ValveSummaryDto(
				"Staging-Limiter",
				order,
				"BLOCKING",
				false,
				false,
				80,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters()
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildDefaultSummary(String name, long currentKey, long lastCompletedKey, int order) {
		return new ValveOverviewDto.ValveSummaryDto(
				name,
				order,
				"BLOCKING",
				false,
				false,
				100,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				50,
				0,
				currentKey,
				lastCompletedKey,
				10_000L,
				500L,
				50,
				0
		);
	}

	// -------------------------------------------------------------------------
	// Deterministic Metric Calculations
	// -------------------------------------------------------------------------

	private record SlotMetrics(long totalRequests, int activeCounters, int blockedCounters, List<ValveDetailsDto.BlockedClientDto> blockedClients) {}

	private SlotMetrics calculateMetrics(String nodeId, String valveName, long slotKey) {
		String norm = normalizeNodeId(nodeId);
		Random rnd = new Random((slotKey * 31L) ^ valveName.hashCode() ^ norm.hashCode());

		return switch (norm) {
			case "api-gateway" -> calculateApiGatewayMetrics(slotKey, rnd);
			case "edge-eu" -> {
				if ("Subnet-Guard".equalsIgnoreCase(valveName)) {
					yield calculateSubnetMetrics(slotKey, rnd);
				}
				yield calculateEdgePrimaryMetrics(slotKey, rnd);
			}
			case "staging-node" -> calculateStagingMetrics(slotKey, rnd);
			default -> new SlotMetrics(400 + rnd.nextInt(200), 40 + rnd.nextInt(20), 0, List.of());
		};
	}

	private SlotMetrics calculateApiGatewayMetrics(long slotKey, Random rnd) {
		// Active Distributed Attack Scenario
		long totalRequests = 4200L + rnd.nextInt(2600);
		int activeCounters = 950 + rnd.nextInt(350);

		// 8 to 14 blocked IPs per slot
		int blockedCount = 8 + rnd.nextInt(7);
		List<ValveDetailsDto.BlockedClientDto> blocked = new ArrayList<>();

		String lastUpdate = DateTimeFormatter.ISO_INSTANT.format(
				Instant.ofEpochMilli(slotKey * SLOT_LENGTH_MILLIS + (SLOT_LENGTH_MILLIS - 500))
		);

		for (int i = 0; i < blockedCount && i < ATTACKER_IPS.length; i++) {
			String ip = ATTACKER_IPS[i];
			int reqCount = 120 + rnd.nextInt(850);
			int retained = 5 + rnd.nextInt(25);
			boolean locked = rnd.nextBoolean();
			blocked.add(new ValveDetailsDto.BlockedClientDto(ip, reqCount, retained, locked, lastUpdate));
		}

		return new SlotMetrics(totalRequests, activeCounters, blocked.size(), blocked);
	}

	private SlotMetrics calculateEdgePrimaryMetrics(long slotKey, Random rnd) {
		long totalRequests = 950L + rnd.nextInt(450);
		int activeCounters = 320 + rnd.nextInt(80);

		List<ValveDetailsDto.BlockedClientDto> blocked = new ArrayList<>();
		// Occasional crawler exceeding limit (approx 25% of slots)
		if (slotKey % 4 == 0) {
			String lastUpdate = DateTimeFormatter.ISO_INSTANT.format(
					Instant.ofEpochMilli(slotKey * SLOT_LENGTH_MILLIS + 4000)
			);
			blocked.add(new ValveDetailsDto.BlockedClientDto("198.51.100.42", 145, 0, false, lastUpdate));
			if (rnd.nextBoolean()) {
				blocked.add(new ValveDetailsDto.BlockedClientDto("203.0.113.88", 128, 0, false, lastUpdate));
			}
		}

		return new SlotMetrics(totalRequests, activeCounters, blocked.size(), blocked);
	}

	private SlotMetrics calculateSubnetMetrics(long slotKey, Random rnd) {
		long totalRequests = 1300L + (slotKey % 10) * 15L + rnd.nextInt(300);
		int activeCounters = 180 + rnd.nextInt(40);
		return new SlotMetrics(totalRequests, activeCounters, 0, List.of());
	}

	private SlotMetrics calculateStagingMetrics(long slotKey, Random rnd) {
		long totalRequests = 75L + (slotKey % 5) * 5L + rnd.nextInt(40);
		int activeCounters = 25 + rnd.nextInt(15);
		return new SlotMetrics(totalRequests, activeCounters, 0, List.of());
	}
}
