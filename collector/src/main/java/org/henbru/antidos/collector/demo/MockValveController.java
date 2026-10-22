package org.henbru.antidos.collector.demo;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * In-app mock REST controller exposing AntiDoSValve-compatible status endpoints
 * when demo mode is active.
 */
@RestController
@RequestMapping("/mock-valve")
@ConditionalOnProperty(name = "collector.demo-mode", havingValue = "true")
public class MockValveController {

	private static final Logger log = LoggerFactory.getLogger(MockValveController.class);
	public static final String EXPECTED_TOKEN = "demo-token";

	private final MockValveSimulator simulator;

	public MockValveController(MockValveSimulator simulator) {
		this.simulator = simulator;
	}

	@GetMapping("/{nodeId}/antidos-status")
	public ResponseEntity<?> getStatus(
			@PathVariable("nodeId") String nodeId,
			@RequestParam(value = "view", required = false) String view,
			@RequestParam(value = "valve", required = false) String valve,
			@RequestParam(value = "slot", required = false) String slot,
			@RequestParam(value = "limit", required = false) String limit,
			@RequestParam(value = "blockedLimit", required = false) String blockedLimit,
			@RequestParam(value = "activeLimit", required = false) String activeLimit,
			@RequestParam(value = "activeMinCount", required = false) Integer activeMinCount,
			@RequestParam(value = "format", required = false) String format,
			@RequestHeader(value = "Authorization", required = false) String authHeader
	) {
		String serverTime = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

		// 1. Bearer Token Verification
		if (authHeader == null || !authHeader.trim().equals("Bearer " + EXPECTED_TOKEN)) {
			log.debug("Mock valve endpoint '{}': Rejected unauthorized request (invalid or missing Bearer token)", nodeId);
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new ValveOverviewDto(serverTime, null, "HTTP 401 Unauthorized: Invalid or missing token"));
		}

		// 2. Simulated Node Chaos for 'staging-node'
		if (nodeId != null && nodeId.toLowerCase().contains("staging")) {
			long cycle = System.currentTimeMillis() / 15_000L;

			// Intermittent simulated server downtime (approx. every 17 cycles)
			if (cycle % 17 == 0) {
				log.info("Simulating transient 503 Service Unavailable for staging node (demonstrates collector error audit)");
				return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
						.body("HTTP 503 Service Unavailable: Simulated staging node maintenance");
			}

			// Intermittent simulated slow response (approx. every 7 cycles)
			if (cycle % 7 == 0) {
				try {
					log.info("Simulating slow response (~1150ms) for staging node (demonstrates slow poll warning threshold)");
					Thread.sleep(1150);
				} catch (InterruptedException ignored) {
					Thread.currentThread().interrupt();
				}
			}
		}

		// 3. Dispatch to details or overview payload
		if ("details".equalsIgnoreCase(view)) {
			ValveDetailsDto details = simulator.buildDetails(nodeId, valve, slot, limit, blockedLimit, activeLimit, activeMinCount);
			return ResponseEntity.ok(details);
		}

		ValveOverviewDto overview = simulator.buildOverview(nodeId, valve);
		return ResponseEntity.ok(overview);
	}
}
