package org.henbru.antidos.collector.web;

import org.henbru.antidos.collector.aggregation.RollupAggregationService;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.enrichment.EntityResolver;
import org.henbru.antidos.collector.poller.CollectorScheduler;
import org.henbru.antidos.collector.system.SystemStatusDto;
import org.henbru.antidos.collector.system.SystemStatusService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Controller serving the System Status & Configuration dashboard, displaying data retention schedules,
 * telemetry cascades, threat intel indices, and operational maintenance triggers.
 */
@Controller
@SuppressWarnings("null")
public class SystemController {

	private final SystemStatusService systemStatusService;
	private final CollectorScheduler collectorScheduler;
	private final RollupAggregationService rollupAggregationService;
	private final EntityResolver entityResolver;
	private final CollectorProperties properties;

	public SystemController(
			SystemStatusService systemStatusService,
			CollectorScheduler collectorScheduler,
			RollupAggregationService rollupAggregationService,
			EntityResolver entityResolver,
			CollectorProperties properties) {
		this.systemStatusService = systemStatusService;
		this.collectorScheduler = collectorScheduler;
		this.rollupAggregationService = rollupAggregationService;
		this.entityResolver = entityResolver;
		this.properties = properties;
	}

	@ModelAttribute("demoMode")
	public boolean demoMode() {
		return properties.isDemoMode();
	}

	@GetMapping({"/system", "/settings"})
	public String systemPage(Model model) {
		populateModel(model);
		return "system";
	}

	@PostMapping("/system/retention-cleanup")
	public String triggerRetentionCleanup(Model model) {
		try {
			CollectorScheduler.RetentionCleanupResult result = collectorScheduler.runRetentionCleanup();
			model.addAttribute("actionSuccess", true);
			model.addAttribute("actionMessage", String.format(
					"Retention cleanup executed successfully in %dms: purged %d snapshots, %d events, %d logs, %d orphan entities, and expired %d stale entities.",
					result.durationMs(), result.deletedSlots(), result.deletedEvents(),
					result.deletedLogs(), result.deletedEntities(), result.expiredEntities()
			));
		} catch (Exception e) {
			model.addAttribute("actionSuccess", false);
			model.addAttribute("actionMessage", "Failed to execute retention cleanup: " + e.getMessage());
		}
		populateModel(model);
		return "fragments/retention-card :: retentionCard";
	}

	@PostMapping("/system/rollup-catchup")
	public String triggerRollupCatchUp(Model model) {
		try {
			RollupAggregationService.RollupExecutionResult result = rollupAggregationService.executeManualCatchUp(6);
			model.addAttribute("actionSuccess", true);
			model.addAttribute("actionMessage", String.format(
					"Subnet rollup catch-up executed successfully in %dms: persisted %d subnet rollups across the last 6 hours.",
					result.durationMs(), result.persistedRollups()
			));
		} catch (Exception e) {
			model.addAttribute("actionSuccess", false);
			model.addAttribute("actionMessage", "Failed to execute subnet rollup catch-up: " + e.getMessage());
		}
		populateModel(model);
		return "fragments/retention-card :: retentionCard";
	}

	@PostMapping("/system/clear-cache")
	public String triggerClearCache(Model model) {
		try {
			if (entityResolver != null) {
				entityResolver.clearCache();
			}
			model.addAttribute("actionSuccess", true);
			model.addAttribute("actionMessage", "Entity resolution in-memory cache cleared successfully. Subsequent requests will query persistent storage and MMDB.");
		} catch (Exception e) {
			model.addAttribute("actionSuccess", false);
			model.addAttribute("actionMessage", "Failed to clear entity cache: " + e.getMessage());
		}
		populateModel(model);
		return "fragments/retention-card :: retentionCard";
	}

	private void populateModel(Model model) {
		SystemStatusDto status = systemStatusService.getSystemStatus();
		model.addAttribute("status", status);
	}
}
