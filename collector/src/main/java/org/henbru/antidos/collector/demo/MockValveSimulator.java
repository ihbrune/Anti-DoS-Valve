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

	// IP pool for the simulated distributed attack on API Gateway (mixed IPv4 and IPv6)
	private static final String[] ATTACKER_IPS = {
			"45.154.255.12", "185.220.101.5", "194.26.29.110", "91.240.118.77",
			"2a03:2880:f12f:83:face:b00c:0:25de", // IPv6 attacker
			"185.246.221.84", "103.149.28.19", "193.106.191.66", "195.123.245.9",
			"2600:1f18:43b6:6100:9981:ef71:47d2:81a2", // IPv6 attacker
			"178.62.204.14", "167.99.165.88", "146.190.112.51", "159.65.130.22",
			"2a01:4f8:c010:d56::1", // IPv6 attacker
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
					valves.add(buildEdgePrimarySummary(nodeId, currentSlotKey, lastCompletedSlotKey, 1));
				}
				if (matchesFilter(filterValve, "Subnet-Guard")) {
					valves.add(buildEdgeSubnetSummary(nodeId, currentSlotKey, lastCompletedSlotKey, 2));
				}
				if (matchesFilter(filterValve, "IPv6-Rate-Limiter")) {
					valves.add(buildEdgeIpv6Summary(nodeId, currentSlotKey, lastCompletedSlotKey, 3));
				}
				if (matchesFilter(filterValve, "HONEYPOT-PROBE-VALVE")) {
					valves.add(buildEdgeHoneypotSummary(nodeId, currentSlotKey, lastCompletedSlotKey, 4));
				}
			}
			case "api-gateway" -> {
				if (matchesFilter(filterValve, "API-DoS-Shield")) {
					valves.add(buildApiShieldSummary(nodeId, currentSlotKey, lastCompletedSlotKey, 1));
				}
			}
			case "staging-node" -> {
				if (matchesFilter(filterValve, "Staging-Limiter")) {
					valves.add(buildStagingSummary(nodeId, currentSlotKey, lastCompletedSlotKey, 1));
				}
			}
			default -> {
				valves.add(buildDefaultSummary("Generic-Limiter", currentSlotKey, lastCompletedSlotKey, 1));
			}
		}

		return new ValveOverviewDto(serverTime, valves, null);
	}

	public ValveDetailsDto buildDetails(String nodeId, String valveName, String slotParam, String limitParam) {
		return buildDetails(nodeId, valveName, slotParam, limitParam, null, null);
	}

	public ValveDetailsDto buildDetails(String nodeId, String valveName, String slotParam, String limitParam,
			String blockedLimitParam, String activeLimitParam) {
		return buildDetails(nodeId, valveName, slotParam, limitParam, blockedLimitParam, activeLimitParam, null);
	}

	public ValveDetailsDto buildDetails(String nodeId, String valveName, String slotParam, String limitParam,
			String blockedLimitParam, String activeLimitParam, Integer activeMinCount) {
		long now = System.currentTimeMillis();
		long currentSlotKey = now / SLOT_LENGTH_MILLIS;
		long lastCompletedSlotKey = currentSlotKey - 1;
		String serverTime = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(now));

		String resolvedValve = resolveValveName(nodeId, valveName);
		boolean visitorCookieActive = !"api-gateway".equalsIgnoreCase(normalizeNodeId(nodeId));
		ValveDetailsDto.ValveHeaderDto header = new ValveDetailsDto.ValveHeaderDto(
				resolvedValve,
				currentSlotKey,
				lastCompletedSlotKey,
				SLOT_LENGTH_MILLIS,
				NUMBER_OF_SLOTS,
				visitorCookieActive
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

		List<ValveDetailsDto.BlockedClientDto> blockedList = ("0".equals(blockedLimitParam))
				? List.of()
				: metrics.blockedClients();

		String effectiveBlockedLimit = (blockedLimitParam != null && !blockedLimitParam.isBlank())
				? blockedLimitParam
				: (limitParam != null && !limitParam.isBlank() ? limitParam : "all");

		int totalActive = metrics.activeCounters();
		String effectiveActiveLimit = (activeLimitParam != null && !activeLimitParam.isBlank()) ? activeLimitParam : "0";
		List<ValveDetailsDto.ActiveClientDto> activeList = List.of();
		if (!"0".equals(effectiveActiveLimit) && totalActive > 0) {
			int min = (activeMinCount != null && activeMinCount > 0) ? activeMinCount : 1;
			int c1 = Math.max(min, 2);
			int c2 = Math.max(min, 5);
			activeList = List.of(
					new ValveDetailsDto.ActiveClientDto("192.168.1.50", c1, 0, c1, 60, 5, 1, visitorCookieActive ? c1 : null, null),
					new ValveDetailsDto.ActiveClientDto("10.0.0.12", c2, 1, c2 + 1, 60, 10, 1, visitorCookieActive ? (c2 - 1) : null, null)
			);
		}

		return new ValveDetailsDto(
				serverTime,
				header,
				selectedSlot,
				metrics.blockedClients().size(),
				effectiveBlockedLimit,
				null,
				null,
				blockedList,
				totalActive,
				effectiveActiveLimit,
				null,
				null,
				activeMinCount,
				activeList,
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

	private ValveOverviewDto.ValveSummaryDto buildEdgePrimarySummary(String nodeId, long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics(nodeId, "Primary-Rate-Limiter", currentKey);
		SlotMetrics prev = calculateMetrics(nodeId, "Primary-Rate-Limiter", lastCompletedKey);

		long offset = (nodeId != null) ? Math.abs(nodeId.hashCode() % 10_000L) : 0L;
		long cumulative = 240_000L + offset + (currentKey % 50_000L) * 1100L;
		return new ValveOverviewDto.ValveSummaryDto(
				"Primary-Rate-Limiter",
				"Primary per-IP sliding window rate limiter protecting web assets and API endpoints.",
				order,
				"BLOCKING",
				false,
				false,
				429,
				120,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				0.8f,
				32,
				64,
				20000,
				10000,
				null,
				"*.css, *.js, *.png, *.ico, *.svg, *.woff2",
				"127.0.0.1, 10.0.0.0/8, 192.168.0.0/16",
				null,
				"/antidos-status",
				"127.0.0.1, 10.0.0.0/8",
				0L,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters(),
				NUMBER_OF_SLOTS,
				true,
				true
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildEdgeSubnetSummary(String nodeId, long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics(nodeId, "Subnet-Guard", currentKey);
		SlotMetrics prev = calculateMetrics(nodeId, "Subnet-Guard", lastCompletedKey);

		long offset = (nodeId != null) ? Math.abs(nodeId.hashCode() % 10_000L) : 0L;
		long cumulative = 310_000L + offset + (currentKey % 50_000L) * 1400L;
		return new ValveOverviewDto.ValveSummaryDto(
				"Subnet-Guard",
				"Subnet-level DDoS traffic partition absorbing distributed botnet clusters across /24 and /48 prefixes.",
				order,
				"BLOCKING",
				false,
				false,
				429,
				250,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				0.75f,
				24,
				48,
				15000,
				10000,
				null,
				null,
				"127.0.0.1, 10.0.0.0/8",
				null,
				"/antidos-status",
				null,
				0L,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters(),
				NUMBER_OF_SLOTS,
				false,
				false
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildEdgeIpv6Summary(String nodeId, long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics(nodeId, "IPv6-Rate-Limiter", currentKey);
		SlotMetrics prev = calculateMetrics(nodeId, "IPv6-Rate-Limiter", lastCompletedKey);

		long offset = (nodeId != null) ? Math.abs(nodeId.hashCode() % 10_000L) : 0L;
		long cumulative = 180_000L + offset + (currentKey % 50_000L) * 900L;
		return new ValveOverviewDto.ValveSummaryDto(
				"IPv6-Rate-Limiter",
				"Dedicated IPv6 subnet rate limiter guarding against rotating privacy extension prefixes.",
				order,
				"BLOCKING",
				false,
				false,
				429,
				120,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				0.8f,
				32,
				64,
				10000,
				10000,
				null,
				null,
				"::1, fe80::/10",
				null,
				"/antidos-status",
				null,
				0L,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters(),
				NUMBER_OF_SLOTS,
				false,
				false
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildEdgeHoneypotSummary(String nodeId, long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics(nodeId, "HONEYPOT-PROBE-VALVE", currentKey);
		SlotMetrics prev = calculateMetrics(nodeId, "HONEYPOT-PROBE-VALVE", lastCompletedKey);

		long offset = (nodeId != null) ? Math.abs(nodeId.hashCode() % 10_000L) : 0L;
		long cumulative = 24_000L + offset + (currentKey % 50_000L) * 120L;
		return new ValveOverviewDto.ValveSummaryDto(
				"HONEYPOT-PROBE-VALVE",
				"Zero-tolerance honeypot trap blocking scanners and probers across the entire server on first access (*.php, *.cgi, *.aspx, /.env).",
				order,
				"BLOCKING",
				false,
				true,
				429,
				0,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				0.0f,
				32,
				64,
				500,
				1000,
				".*\\.(php|cgi|aspx)$|.*/wp-.*|.*/\\.env.*",
				null,
				"127.0.0.1",
				null,
				"/antidos-status",
				null,
				0L,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters(),
				NUMBER_OF_SLOTS,
				false,
				false
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildApiShieldSummary(String nodeId, long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics(nodeId, "API-DoS-Shield", currentKey);
		SlotMetrics prev = calculateMetrics(nodeId, "API-DoS-Shield", lastCompletedKey);

		long offset = (nodeId != null) ? Math.abs(nodeId.hashCode() % 25_000L) : 0L;
		long cumulative = 1_850_000L + offset + (currentKey % 50_000L) * 5200L;
		return new ValveOverviewDto.ValveSummaryDto(
				"API-DoS-Shield",
				"Strict API gateway rate limiter enforcing tight quotas on backend REST endpoints.",
				order,
				"BLOCKING",
				false,
				true,
				429,
				60,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				0.85f,
				32,
				64,
				25000,
				15000,
				"/api/*, /v1/*, /graphql",
				null,
				"127.0.0.1, 10.0.0.0/8",
				"198.51.100.99",
				"/antidos-status",
				"127.0.0.1",
				0L,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters(),
				NUMBER_OF_SLOTS,
				true,
				true
		);
	}

	private ValveOverviewDto.ValveSummaryDto buildStagingSummary(String nodeId, long currentKey, long lastCompletedKey, int order) {
		SlotMetrics cur = calculateMetrics(nodeId, "Staging-Limiter", currentKey);
		SlotMetrics prev = calculateMetrics(nodeId, "Staging-Limiter", lastCompletedKey);

		long offset = (nodeId != null) ? Math.abs(nodeId.hashCode() % 2_000L) : 0L;
		long cumulative = 45_000L + offset + (currentKey % 50_000L) * 85L;
		return new ValveOverviewDto.ValveSummaryDto(
				"Staging-Limiter",
				"Staging environment limiter operating in marking simulation mode.",
				order,
				"MARKING",
				true,
				false,
				429,
				80,
				SLOT_LENGTH_SECONDS,
				NUMBER_OF_SLOTS,
				0.8f,
				32,
				64,
				5000,
				5000,
				null,
				null,
				"127.0.0.1",
				null,
				"/antidos-status",
				null,
				0L,
				cur.activeCounters(),
				cur.blockedCounters(),
				currentKey,
				lastCompletedKey,
				cumulative,
				prev.totalRequests(),
				prev.activeCounters(),
				prev.blockedCounters(),
				NUMBER_OF_SLOTS,
				true,
				true
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
		String effectiveNode = (nodeId != null && !nodeId.isBlank()) ? nodeId : norm;
		Random rnd = new Random((slotKey * 31L) ^ valveName.hashCode() ^ effectiveNode.hashCode());

		return switch (norm) {
			case "api-gateway" -> calculateApiGatewayMetrics(slotKey, rnd);
			case "edge-eu" -> {
				if ("Subnet-Guard".equalsIgnoreCase(valveName)) {
					yield calculateSubnetMetrics(slotKey, rnd);
				}
				if ("IPv6-Rate-Limiter".equalsIgnoreCase(valveName)) {
					yield calculateIpv6Metrics(slotKey, rnd);
				}
				if ("HONEYPOT-PROBE-VALVE".equalsIgnoreCase(valveName)) {
					yield calculateHoneypotMetrics(slotKey, rnd);
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
			int dc = getDistinctClientsForAttacker(ip);
			blocked.add(new ValveDetailsDto.BlockedClientDto(ip, reqCount, retained, reqCount + retained, locked, lastUpdate, dc));
		}

		return new SlotMetrics(totalRequests, activeCounters, blocked.size(), blocked);
	}

	private int getDistinctClientsForAttacker(String ip) {
		return switch (ip) {
			case "185.246.221.84" -> 82;
			case "103.149.28.19" -> 64;
			case "91.240.118.77" -> 44;
			case "45.154.255.12" -> 34;
			case "195.123.245.9" -> 12;
			case "194.26.29.110" -> 8;
			case "178.62.204.14" -> 6;
			case "185.220.101.5" -> 3;
			case "167.99.165.88", "159.65.130.22" -> 4;
			case "146.190.112.51", "45.148.10.66" -> 3;
			case "193.32.162.201", "2a01:4f8:c010:d56::1" -> 5;
			default -> 1;
		};
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
			blocked.add(new ValveDetailsDto.BlockedClientDto("198.51.100.42", 145, 0, 145, false, lastUpdate, 24, 120, null));
			if (rnd.nextBoolean()) {
				blocked.add(new ValveDetailsDto.BlockedClientDto("203.0.113.88", 128, 0, 128, false, lastUpdate, 28, 0, null));
			}
		}

		return new SlotMetrics(totalRequests, activeCounters, blocked.size(), blocked);
	}

	private SlotMetrics calculateSubnetMetrics(long slotKey, Random rnd) {
		long totalRequests = 1600L + (slotKey % 10) * 25L + rnd.nextInt(400);
		int activeCounters = 190 + rnd.nextInt(45);

		List<ValveDetailsDto.BlockedClientDto> blocked = new ArrayList<>();
		String lastUpdate = DateTimeFormatter.ISO_INSTANT.format(
				Instant.ofEpochMilli(slotKey * SLOT_LENGTH_MILLIS + 3500)
			);
		// Baseline aggregated /24 subnet exceeding threshold (legitimate heavy traffic with ~82% cookies)
		int req1 = 320 + rnd.nextInt(90);
		blocked.add(new ValveDetailsDto.BlockedClientDto(
				"198.51.100.0/24", req1, 0, req1, true, lastUpdate, 24 + rnd.nextInt(8), (int) (req1 * 0.82), null
		));
		if (slotKey % 2 == 0) {
			// Residential proxy swarm cluster: 260 reqs spread across 75-90 distinct client IPs (~3.2 reqs/IP) - 0% cookies!
			int req2 = 260 + rnd.nextInt(70);
			blocked.add(new ValveDetailsDto.BlockedClientDto(
					"185.246.221.0/24", req2, 0, req2, false, lastUpdate, 82 + rnd.nextInt(8), 0, null
			));
		}
		if (slotKey % 3 == 0) {
			// Comcast residential proxy swarm: 180 reqs spread across 90-100 distinct client IPs (~1.9 reqs/IP)
			int reqComcast = 180 + rnd.nextInt(40);
			blocked.add(new ValveDetailsDto.BlockedClientDto(
					"73.15.20.0/24", reqComcast, 0, reqComcast, false, lastUpdate, 96 + rnd.nextInt(6), 0, null
			));
		}
		if (slotKey % 5 == 0) {
			int req3 = 290 + rnd.nextInt(80);
			blocked.add(new ValveDetailsDto.BlockedClientDto(
					"45.154.255.0/24", req3, 0, req3, true, lastUpdate, 34 + rnd.nextInt(8), 0, null
			));
		}

		return new SlotMetrics(totalRequests, activeCounters, blocked.size(), blocked);
	}

	private SlotMetrics calculateIpv6Metrics(long slotKey, Random rnd) {
		long totalRequests = 600L + rnd.nextInt(350);
		int activeCounters = 110 + rnd.nextInt(40);

		List<ValveDetailsDto.BlockedClientDto> blocked = new ArrayList<>();
		String lastUpdate = DateTimeFormatter.ISO_INSTANT.format(
				Instant.ofEpochMilli(slotKey * SLOT_LENGTH_MILLIS + 4500)
		);
		// Baseline blocked IPv6 scraper
		blocked.add(new ValveDetailsDto.BlockedClientDto("2a02:1205:502c:3b00:1c44:98ff:fe22:1011", 165 + rnd.nextInt(30), 0, true, lastUpdate));
		// Rotating second client from the same residential /64 prefix to demonstrate Subnet Rollup
		blocked.add(new ValveDetailsDto.BlockedClientDto("2a02:1205:502c:3b00:2d55:77aa:1122:3344", 142 + rnd.nextInt(25), 0, true, lastUpdate));
		if (slotKey % 2 == 0) {
			blocked.add(new ValveDetailsDto.BlockedClientDto("2001:db8:85a3::8a2e:370:7334", 138 + rnd.nextInt(20), 0, true, lastUpdate));
		}

		return new SlotMetrics(totalRequests, activeCounters, blocked.size(), blocked);
	}

	private SlotMetrics calculateHoneypotMetrics(long slotKey, Random rnd) {
		int probeCount = 1 + rnd.nextInt(3);
		List<ValveDetailsDto.BlockedClientDto> blocked = new ArrayList<>();
		String lastUpdate = DateTimeFormatter.ISO_INSTANT.format(
				Instant.ofEpochMilli(slotKey * SLOT_LENGTH_MILLIS + 1500)
		);
		String[] scannerIps = {
				"185.220.101.5",
				"89.248.163.74",
				"194.26.29.112",
				"45.154.255.88"
		};
		for (int i = 0; i < probeCount; i++) {
			String ip = scannerIps[(int) ((slotKey + i) % scannerIps.length)];
			blocked.add(new ValveDetailsDto.BlockedClientDto(
					ip, 1, 0, 1, true, lastUpdate, 1, 0, null
			));
		}
		return new SlotMetrics(probeCount, 0, blocked.size(), blocked);
	}

	private SlotMetrics calculateStagingMetrics(long slotKey, Random rnd) {
		long totalRequests = 75L + (slotKey % 5) * 5L + rnd.nextInt(40);
		int activeCounters = 25 + rnd.nextInt(15);
		return new SlotMetrics(totalRequests, activeCounters, 0, List.of());
	}
}
