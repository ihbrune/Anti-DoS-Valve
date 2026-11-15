package org.henbru.antidos.collector.web;

import org.henbru.antidos.collector.aggregation.RollupAggregationService;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.enrichment.EntityResolver;
import org.henbru.antidos.collector.poller.CollectorScheduler;
import org.henbru.antidos.collector.system.SystemStatusDto;
import org.henbru.antidos.collector.system.SystemStatusService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import jakarta.servlet.http.HttpServletResponse;

/**
 * Controller serving the System Status & Configuration dashboard, displaying data retention schedules,
 * telemetry cascades, threat intel indices, and operational maintenance triggers.
 */
@Controller
@ConditionalOnWebApplication
public class SystemController {

	private final SystemStatusService systemStatusService;
	private final CollectorScheduler collectorScheduler;
	private final RollupAggregationService rollupAggregationService;
	private final EntityResolver entityResolver;
	private final org.henbru.antidos.collector.system.DatabaseMaintenanceService databaseMaintenanceService;
	private final CollectorProperties properties;

	public SystemController(
			SystemStatusService systemStatusService,
			CollectorScheduler collectorScheduler,
			RollupAggregationService rollupAggregationService,
			EntityResolver entityResolver,
			@org.springframework.beans.factory.annotation.Autowired(required = false) org.henbru.antidos.collector.system.DatabaseMaintenanceService databaseMaintenanceService,
			CollectorProperties properties) {
		this.systemStatusService = systemStatusService;
		this.collectorScheduler = collectorScheduler;
		this.rollupAggregationService = rollupAggregationService;
		this.entityResolver = entityResolver;
		this.databaseMaintenanceService = databaseMaintenanceService;
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
	public String triggerRetentionCleanup(HttpServletResponse response, Model model) {
		if (rejectViewerMaintenance(response, model, "Retention cleanup")) {
			return "fragments/retention-card :: retentionCard";
		}
		try {
			CollectorScheduler.RetentionCleanupResult result = collectorScheduler.runRetentionCleanup();
			model.addAttribute("actionSuccess", true);
			String vacuumSuffix = result.vacuumExecuted() ? ", and compacted SQLite database (VACUUM)" : "";
			model.addAttribute("actionMessage", String.format(
					"Retention cleanup executed successfully in %dms: purged %d snapshots, %d events (%d active), %d logs, %d orphan entities, and expired %d stale entities%s.",
					result.durationMs(), result.deletedSlots(), result.deletedEvents(), result.deletedActiveEvents(),
					result.deletedLogs(), result.deletedEntities(), result.expiredEntities(), vacuumSuffix
			));
		} catch (Exception e) {
			model.addAttribute("actionSuccess", false);
			model.addAttribute("actionMessage", "Failed to execute retention cleanup: " + e.getMessage());
		}
		populateModel(model);
		return "fragments/retention-card :: retentionCard";
	}

	@PostMapping("/system/vacuum")
	public String triggerVacuum(HttpServletResponse response, Model model) {
		if (rejectViewerMaintenance(response, model, "Database compaction (VACUUM)")) {
			return "fragments/retention-card :: retentionCard";
		}
		try {
			if (databaseMaintenanceService == null || !databaseMaintenanceService.isSqlite()) {
				model.addAttribute("actionSuccess", false);
				model.addAttribute("actionMessage", "Database compaction (VACUUM) is only applicable for SQLite standalone deployments.");
			} else {
				org.henbru.antidos.collector.system.DatabaseMaintenanceService.VacuumResult res = databaseMaintenanceService.vacuum();
				model.addAttribute("actionSuccess", res.success());
				model.addAttribute("actionMessage", res.message());
			}
		} catch (Exception e) {
			model.addAttribute("actionSuccess", false);
			model.addAttribute("actionMessage", "Failed to execute database VACUUM: " + e.getMessage());
		}
		populateModel(model);
		return "fragments/retention-card :: retentionCard";
	}

	@PostMapping("/system/rollup-catchup")
	public String triggerRollupCatchUp(HttpServletResponse response, Model model) {
		if (rejectViewerMaintenance(response, model, "Subnet rollup catch-up")) {
			return "fragments/retention-card :: retentionCard";
		}
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
	public String triggerClearCache(HttpServletResponse response, Model model) {
		if (rejectViewerMaintenance(response, model, "Cache invalidation")) {
			return "fragments/retention-card :: retentionCard";
		}
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

	private boolean rejectViewerMaintenance(HttpServletResponse response, Model model, String actionName) {
		if (!properties.canPerformSystemAdmin()) {
			response.setStatus(HttpStatus.FORBIDDEN.value());
			model.addAttribute("actionSuccess", false);
			model.addAttribute("actionMessage", actionName + " is disabled in " + properties.getMode() + " mode.");
			populateModel(model);
			return true;
		}
		return false;
	}

	private void populateModel(Model model) {
		SystemStatusDto status = systemStatusService.getSystemStatus();
		model.addAttribute("status", status);
	}
}
