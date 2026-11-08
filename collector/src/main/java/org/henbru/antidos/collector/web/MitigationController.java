package org.henbru.antidos.collector.web;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.mitigation.AutoMitigationService;
import org.henbru.antidos.collector.mitigation.MitigationService;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Web &amp; HTMX controller for managing dynamic CIDR mitigations, ASN batch blocks,
 * pre-flight collateral damage checks, deterrence monitoring, and audit trails.
 */
@Controller
public class MitigationController {

	private final MitigationService mitigationService;
	private final AutoMitigationService autoMitigationService;
	private final CollectorProperties properties;

	public MitigationController(
			MitigationService mitigationService,
			AutoMitigationService autoMitigationService,
			CollectorProperties properties) {
		this.mitigationService = mitigationService;
		this.autoMitigationService = autoMitigationService;
		this.properties = properties;
	}

	@GetMapping("/mitigation")
	public String mitigationPage(
			@RequestParam(value = "cidr", required = false) String prefillCidr,
			@RequestParam(value = "asn", required = false) Long prefillAsn,
			@RequestParam(value = "reason", required = false) String prefillReason,
			@RequestParam(value = "ttlMinutes", required = false) Integer prefillTtlMinutes,
			@RequestParam(value = "source", required = false) String prefillSource,
			Model model) {

		populateMitigationModel(model, null, null);
		int defaultTtl = (prefillTtlMinutes != null && prefillTtlMinutes > 0)
				? prefillTtlMinutes
				: properties.getDefaultMitigationTtlMinutes();
		model.addAttribute("prefillCidr", prefillCidr != null ? prefillCidr.trim() : "");
		model.addAttribute("prefillAsn", prefillAsn);
		model.addAttribute("prefillReason", prefillReason != null ? prefillReason.trim() : "");
		model.addAttribute("prefillTtlMinutes", defaultTtl);
		model.addAttribute("prefillSource", prefillSource != null ? prefillSource.trim() : MitigationRule.SOURCE_MANUAL);

		if (prefillCidr != null && !prefillCidr.isBlank()) {
			List<String> lines = parseInputCidrs(prefillCidr);
			model.addAttribute("preflightResult", mitigationService.evaluatePreflight(lines));
		}
		if (prefillAsn != null && prefillAsn > 0) {
			model.addAttribute("asnPreview", mitigationService.previewAsnBatch(prefillAsn, 24));
		}

		return "mitigation";
	}

	@GetMapping("/fragments/mitigation-content")
	public String mitigationContentFragment(Model model) {
		populateMitigationModel(model, null, null);
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/preflight")
	public String evaluatePreflight(
			@RequestParam(value = "cidrInput", required = false) String cidrInput,
			Model model) {
		List<String> cidrs = parseInputCidrs(cidrInput);
		MitigationService.PreflightCheckResult preflight = mitigationService.evaluatePreflight(cidrs);
		model.addAttribute("preflightResult", preflight);
		model.addAttribute("preflightCheckedAt",
				java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")));
		return "fragments/mitigation-content :: preflightBox";
	}

	@PostMapping("/mitigation/asn-preview")
	public String previewAsn(
			@RequestParam(value = "asn", required = false) Long asn,
			@RequestParam(value = "hours", defaultValue = "24") int hours,
			Model model) {
		if (asn != null && asn > 0) {
			model.addAttribute("asnPreview", mitigationService.previewAsnBatch(asn, hours));
		} else {
			model.addAttribute("asnPreviewError", "Please enter a valid ASN number (e.g. 64496) before previewing.");
		}
		return "fragments/mitigation-content :: asnPreviewBox";
	}

	@PostMapping("/mitigation/block")
	public String createBlock(
			@RequestParam("cidrInput") String cidrInput,
			@RequestParam(value = "ttlMinutes", defaultValue = "60") int ttlMinutes,
			@RequestParam(value = "reason", required = false) String reason,
			@RequestParam(value = "source", defaultValue = "MANUAL") String source,
			@RequestParam(value = "confirmOverride", defaultValue = "false") boolean confirmOverride,
			Model model) {

		List<String> rawCidrs = parseInputCidrs(cidrInput);
		MitigationService.PreflightCheckResult preflight = mitigationService.evaluatePreflight(rawCidrs);

		if (!preflight.invalidInputs().isEmpty()) {
			populateMitigationModel(model, null, "Validation failed: " + String.join("; ", preflight.invalidInputs()));
			model.addAttribute("preflightResult", preflight);
			return "fragments/mitigation-content :: mitigationDashboard";
		}

		if (preflight.validCidrs().isEmpty()) {
			populateMitigationModel(model, null, "Please enter at least one valid IPv4 (/16..32) or IPv6 (/32..128) CIDR.");
			return "fragments/mitigation-content :: mitigationDashboard";
		}

		if (preflight.hasCriticalWarnings() && !confirmOverride) {
			populateMitigationModel(model, null,
					"Pre-flight safety check detected collateral damage risk (authenticated users, search engines, or private network). Check 'Override Safety Warning' to proceed.");
			model.addAttribute("preflightResult", preflight);
			return "fragments/mitigation-content :: mitigationDashboard";
		}

		try {
			if (preflight.validCidrs().size() == 1) {
				MitigationRule saved = mitigationService.createOrUpdateBlock(
						preflight.validCidrs().getFirst(), ttlMinutes, reason, source, null, "ADMIN");
				populateMitigationModel(model,
						"Dynamic block active for " + saved.cidr() + " (TTL: " + ttlMinutes + " min) and synchronized to fleet.",
						null);
			} else {
				List<MitigationRule> created = mitigationService.createBatchBlocks(
						preflight.validCidrs(), ttlMinutes, reason, source, "MANUAL-BATCH", "ADMIN");
				populateMitigationModel(model,
						"Activated batch of " + created.size() + " dynamic CIDR blocks (TTL: " + ttlMinutes + " min) and synchronized to fleet.",
						null);
			}
		} catch (Exception e) {
			populateMitigationModel(model, null, "Could not create dynamic block: " + e.getMessage());
		}

		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/asn-block")
	public String blockAsnSubnets(
			@RequestParam("asn") long asn,
			@RequestParam(value = "hours", defaultValue = "24") int hours,
			@RequestParam(value = "ttlMinutes", defaultValue = "60") int ttlMinutes,
			@RequestParam(value = "reason", required = false) String reason,
			Model model) {
		try {
			List<MitigationRule> created = mitigationService.blockAsnSubnets(asn, hours, ttlMinutes, reason, "ADMIN");
			if (created.isEmpty()) {
				populateMitigationModel(model, null, null);
				model.addAttribute("asnPreviewError",
						"No eligible unauthenticated subnets found for ASN " + asn + " in the last " + hours + "h.");
			} else {
				populateMitigationModel(model,
						"Blocked " + created.size() + " active unauthenticated subnet(s) from ASN " + asn
								+ " (Batch ID: " + created.getFirst().batchId() + ", TTL: " + ttlMinutes + " min).",
						null);
			}
		} catch (Exception e) {
			populateMitigationModel(model, null, "ASN batch mitigation failed: " + e.getMessage());
		}
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/{id}/extend")
	public String extendRule(
			@PathVariable("id") long id,
			@RequestParam(value = "additionalMinutes", defaultValue = "60") int additionalMinutes,
			Model model) {
		var updated = mitigationService.extendBlock(id, additionalMinutes, "ADMIN");
		if (updated.isPresent()) {
			populateMitigationModel(model,
					"Extended dynamic block " + updated.get().cidr() + " by +" + additionalMinutes + " minutes.",
					null);
		} else {
			populateMitigationModel(model, null, "Rule #" + id + " not found.");
		}
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/{id}/revoke")
	public String revokeRule(
			@PathVariable("id") long id,
			@RequestParam(value = "reason", required = false) String reason,
			Model model) {
		var revoked = mitigationService.revokeBlock(id, reason, "ADMIN");
		if (revoked.isPresent()) {
			populateMitigationModel(model,
					"Revoked dynamic block " + revoked.get().cidr() + " and removed from fleet.",
					null);
		} else {
			populateMitigationModel(model, null, "Rule #" + id + " not found.");
		}
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/batch/revoke")
	public String revokeBatch(
			@RequestParam("batchId") String batchId,
			@RequestParam(value = "reason", required = false) String reason,
			Model model) {
		int count = mitigationService.revokeBatch(batchId, reason, "ADMIN");
		populateMitigationModel(model,
				"Revoked " + count + " rule(s) in batch '" + batchId + "' and synchronized to fleet.",
				null);
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/sync")
	public String syncFleet(Model model) {
		mitigationService.refreshDeterrenceMetrics();
		MitigationService.FleetSyncResult res = mitigationService.syncFleetMitigations();
		if (res.errors().isEmpty()) {
			populateMitigationModel(model,
					"Synchronized " + res.activeRulesCount() + " active rule(s) to " + res.syncedValvesCount()
							+ "/" + res.targetValvesCount() + " mitigation-enabled Valve(s) (revision: " + res.revision() + ").",
					null);
		} else {
			populateMitigationModel(model,
					"Synchronized " + res.syncedValvesCount() + "/" + res.targetValvesCount() + " Valve(s).",
					"Sync warnings: " + String.join("; ", res.errors()));
		}
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/auto/settings")
	public String updateAutoMitigationSettings(
			@RequestParam(value = "enabled", defaultValue = "false") boolean enabled,
			@RequestParam(value = "dryRun", defaultValue = "false") boolean dryRun,
			@RequestParam(value = "carpetMinSubnets", defaultValue = "3") int carpetMinSubnets,
			@RequestParam(value = "carpetMinRequests", defaultValue = "5000") long carpetMinRequests,
			@RequestParam(value = "maxReturningRatioPct", defaultValue = "5.0") double maxReturningRatioPct,
			@RequestParam(value = "maxActiveRules", defaultValue = "50") int maxActiveRules,
			@RequestParam(value = "defaultTtlMinutes", defaultValue = "60") int defaultTtlMinutes,
			@RequestParam(value = "autoExtendPersistent", defaultValue = "false") boolean autoExtendPersistent,
			@RequestParam(value = "maxExtensionHours", defaultValue = "24") int maxExtensionHours,
			Model model) {
		try {
			autoMitigationService.updateSettings(
					enabled, dryRun, carpetMinSubnets, carpetMinRequests,
					maxReturningRatioPct, maxActiveRules, defaultTtlMinutes,
					autoExtendPersistent, maxExtensionHours, "ADMIN");
			populateMitigationModel(model, "Autonomous defense engine settings saved to system_settings.", null);
		} catch (Exception e) {
			populateMitigationModel(model, null, "Failed to update autonomous defense settings: " + e.getMessage());
		}
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/auto/toggle")
	public String toggleAutoMitigationSetting(
			@RequestParam("property") String property,
			Model model) {
		try {
			AutoMitigationService.EffectiveAutoSettings current = autoMitigationService.getEffectiveSettings();
			boolean newEnabled = current.enabled();
			boolean newDryRun = current.dryRun();
			if ("enabled".equalsIgnoreCase(property)) {
				newEnabled = !newEnabled;
			} else if ("dryRun".equalsIgnoreCase(property)) {
				newDryRun = !newDryRun;
			}
			autoMitigationService.updateSettings(
					newEnabled, newDryRun, current.carpetMinSubnets(), current.carpetMinRequests(),
					current.maxReturningRatioPct(), current.maxActiveRules(), current.defaultTtlMinutes(),
					current.autoExtendPersistent(), current.maxExtensionHours(), "ADMIN");
			populateMitigationModel(model, "Toggled " + property + " to " + ("enabled".equalsIgnoreCase(property) ? newEnabled : newDryRun) + ".", null);
		} catch (Exception e) {
			populateMitigationModel(model, null, "Failed to toggle setting: " + e.getMessage());
		}
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/auto/reset")
	public String resetAutoMitigationSettings(Model model) {
		try {
			autoMitigationService.resetToDefaults("ADMIN");
			populateMitigationModel(model, "Autonomous defense settings reset to application.yaml defaults.", null);
		} catch (Exception e) {
			populateMitigationModel(model, null, "Failed to reset settings: " + e.getMessage());
		}
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	@PostMapping("/mitigation/auto/evaluate")
	public String triggerAutoEvaluation(Model model) {
		try {
			AutoMitigationService.EffectiveAutoSettings config = autoMitigationService.getEffectiveSettings();
			var candidates = autoMitigationService.evaluateAndEnforce(config);
			if (config.autoExtendPersistent()) {
				autoMitigationService.evaluateExtensions(config);
			}
			populateMitigationModel(model, "Autonomous evaluation completed. Evaluated " + candidates.size() + " candidate ASN(s).", null);
		} catch (Exception e) {
			populateMitigationModel(model, null, "Evaluation error: " + e.getMessage());
		}
		return "fragments/mitigation-content :: mitigationDashboard";
	}

	// =========================================================================
	// JSON REST API Endpoints
	// =========================================================================

	@GetMapping("/api/v1/mitigation/rules")
	@ResponseBody
	public ResponseEntity<Map<String, Object>> apiGetRules() {
		Instant now = Instant.now();
		List<MitigationRule> active = mitigationService.getActiveRules();
		List<MonitoredValve> valves = mitigationService.getMitigationCapableValves();
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("serverTime", now.toString());
		body.put("expectedRevision", mitigationService.getExpectedRevision(now));
		body.put("activeRulesCount", active.size());
		body.put("mitigationValvesCount", valves.size());
		body.put("activeRules", active);
		return ResponseEntity.ok(body);
	}

	private void populateMitigationModel(Model model, String feedbackSuccess, String feedbackError) {
		Instant now = Instant.now();
		mitigationService.refreshDeterrenceMetrics();
		List<MitigationRule> activeRules = mitigationService.getActiveRules();
		List<MitigationRule> recentRules = mitigationService.getRecentRules(100);
		List<MitigationRule> historicalRules = recentRules.stream()
				.filter(r -> !r.isCurrentlyActive(now))
				.limit(50)
				.toList();
		List<MitigationAuditEntry> auditEntries = mitigationService.getRecentAuditEntries(60);
		List<MonitoredValve> mitigationValves = mitigationService.getMitigationCapableValves();

		long persistentCount = activeRules.stream()
				.filter(r -> MitigationRule.DETERRENCE_PERSISTENT.equals(r.deterrenceState()))
				.count();
		long deterredCount = activeRules.stream()
				.filter(r -> MitigationRule.DETERRENCE_DETERRED.equals(r.deterrenceState()))
				.count();
		long totalDynamicHits = activeRules.stream()
				.mapToLong(MitigationRule::totalBlockedHits)
				.sum();

		// Collect distinct active batch metadata for quick batch overview & revocation
		Map<String, ActiveBatchSummary> activeBatches = new LinkedHashMap<>();
		for (MitigationRule r : activeRules) {
			if (r.batchId() != null && !r.batchId().isBlank()) {
				activeBatches.compute(r.batchId(), (k, existing) -> {
					if (existing == null) {
						return new ActiveBatchSummary(r.batchId(), 1, r.createdAt(), r.expiresAt(), r.reason());
					} else {
						Instant earliestCreated = existing.createdAt().isBefore(r.createdAt()) ? existing.createdAt() : r.createdAt();
						Instant latestExpires = existing.expiresAt().isAfter(r.expiresAt()) ? existing.expiresAt() : r.expiresAt();
						return new ActiveBatchSummary(k, existing.ruleCount() + 1, earliestCreated, latestExpires,
								existing.reason() != null ? existing.reason() : r.reason());
					}
				});
			}
		}

		model.addAttribute("now", now);
		model.addAttribute("activeRules", activeRules);
		model.addAttribute("historicalRules", historicalRules);
		model.addAttribute("auditEntries", auditEntries);
		model.addAttribute("mitigationValves", mitigationValves);
		model.addAttribute("expectedRevision", mitigationService.getExpectedRevision(now));
		model.addAttribute("persistentCount", persistentCount);
		model.addAttribute("deterredCount", deterredCount);
		model.addAttribute("totalDynamicHits", totalDynamicHits);
		model.addAttribute("activeBatches", activeBatches.values());
		model.addAttribute("defaultTtlMinutes", properties.getDefaultMitigationTtlMinutes());
		model.addAttribute("autoSettings", autoMitigationService.getEffectiveSettings());
		model.addAttribute("feedbackSuccess", feedbackSuccess);
		model.addAttribute("feedbackError", feedbackError);
	}

	public record ActiveBatchSummary(
			String batchId,
			int ruleCount,
			Instant createdAt,
			Instant expiresAt,
			String reason
	) {
		public String getBatchId() { return batchId; }
		public int getRuleCount() { return ruleCount; }
		public Instant getCreatedAt() { return createdAt; }
		public Instant getExpiresAt() { return expiresAt; }
		public String getReason() { return reason; }

		public String formattedCreatedAt() {
			if (createdAt == null) return "—";
			return createdAt.atZone(java.time.ZoneId.systemDefault())
					.format(java.time.format.DateTimeFormatter.ofPattern("HH:mm"));
		}

		public String formattedExpiresAt() {
			if (expiresAt == null) return "—";
			return expiresAt.atZone(java.time.ZoneId.systemDefault())
					.format(java.time.format.DateTimeFormatter.ofPattern("HH:mm"));
		}

		public String remainingFormatted(Instant now) {
			if (expiresAt == null || !expiresAt.isAfter(now)) {
				return "Expired";
			}
			long sec = java.time.temporal.ChronoUnit.SECONDS.between(now, expiresAt);
			if (sec < 60) return sec + "s";
			long min = sec / 60;
			if (min < 60) return min + "m";
			long h = min / 60;
			long remM = min % 60;
			return remM > 0 ? h + "h " + remM + "m" : h + "h";
		}
	}

	private static List<String> parseInputCidrs(String input) {
		if (input == null || input.isBlank()) {
			return List.of();
		}
		List<String> result = new ArrayList<>();
		Arrays.stream(input.split("[,\\r\\n\\s]+"))
				.map(String::trim)
				.filter(s -> !s.isEmpty())
				.forEach(result::add);
		return result;
	}
}

