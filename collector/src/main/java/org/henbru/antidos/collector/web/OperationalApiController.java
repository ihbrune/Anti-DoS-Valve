package org.henbru.antidos.collector.web;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.annotation.NetworkAnnotationService;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.mitigation.MitigationService;
import org.henbru.antidos.collector.model.AnnotationTargetType;
import org.henbru.antidos.collector.model.AnnotationVerdict;
import org.henbru.antidos.collector.model.DailyReport;
import org.henbru.antidos.collector.model.DailyReportNote;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.henbru.antidos.collector.report.DailyReportService;
import org.henbru.antidos.collector.security.CollectorAuthContext;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Operational REST JSON API (Stage 2) and AI-Agent Guardrails (Stage 3) under {@code /api/v1}.
 * Covers operational notes, daily reports, and dynamic CIDR mitigation lifecycle.
 */
@RestController
@RequestMapping("/api/v1")
@ConditionalOnWebApplication
public class OperationalApiController {

	private static final String AI_NOTE_PREFIX = "**[AI_AGENT";

	private final CollectorProperties properties;
	private final NetworkAnnotationService annotationService;
	private final DailyReportService dailyReportService;
	private final MitigationService mitigationService;
	private final ObjectMapper objectMapper;

	public OperationalApiController(
			CollectorProperties properties,
			NetworkAnnotationService annotationService,
			DailyReportService dailyReportService,
			MitigationService mitigationService,
			ObjectMapper objectMapper) {
		this.properties = properties;
		this.annotationService = annotationService;
		this.dailyReportService = dailyReportService;
		this.mitigationService = mitigationService;
		this.objectMapper = objectMapper;
	}

	// =========================================================================
	// Network Annotations API (/api/v1/notes)
	// =========================================================================

	@GetMapping("/notes")
	public ResponseEntity<Map<String, Object>> listNotes(
			@RequestParam(required = false) AnnotationTargetType targetType,
			@RequestParam(required = false) AnnotationVerdict verdict,
			@RequestParam(required = false) String q,
			@RequestParam(required = false, defaultValue = "updated") String sort) {
		List<NetworkAnnotation> notes = annotationService.getAnnotationsFiltered(targetType, verdict, q, sort);
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("totalCount", annotationService.getTotalCount());
		body.put("verdictCounts", annotationService.getVerdictCounts());
		body.put("count", notes.size());
		body.put("notes", notes);
		return ResponseEntity.ok(body);
	}

	@GetMapping("/notes/{id}")
	public ResponseEntity<Map<String, Object>> getNote(@PathVariable long id) {
		Optional<NetworkAnnotation> found = annotationService.getAnnotationById(id);
		if (found.isEmpty()) {
			return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Annotation with id " + id + " was not found.");
		}
		return ResponseEntity.ok(Map.of("status", "OK", "note", found.get()));
	}

	@PostMapping("/notes")
	public ResponseEntity<Map<String, Object>> saveNote(
			@RequestParam(required = false) Map<String, String> params,
			HttpServletRequest request) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"Operational writes are disabled in " + properties.getEffectiveMode() + " mode.");
		}

		Map<String, Object> payload;
		try {
			payload = extractPayload(request, params);
		} catch (IOException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid JSON payload: " + e.getMessage());
		}

		Long existingId = parseLong(payload.get("id"));
		String targetTypeRaw = asString(payload.get("targetType"));
		String targetKey = asString(payload.get("targetKey"));
		String verdictRaw = asString(payload.get("verdict"));
		String noteMarkdown = asString(payload.get("noteMarkdown"));
		boolean append = asBoolean(payload.get("append"), false);

		Optional<NetworkAnnotation> existingOpt = Optional.empty();
		if (existingId != null) {
			existingOpt = annotationService.getAnnotationById(existingId);
			if (existingOpt.isEmpty()) {
				return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Annotation with id " + existingId + " was not found.");
			}
		}

		AnnotationTargetType targetType;
		if (targetTypeRaw != null && !targetTypeRaw.isBlank()) {
			try {
				targetType = AnnotationTargetType.valueOf(targetTypeRaw.trim().toUpperCase(Locale.ROOT));
			} catch (IllegalArgumentException e) {
				return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST",
						"Invalid targetType '" + targetTypeRaw + "'. Expected ASN or SUBNET.");
			}
		} else if (existingOpt.isPresent()) {
			targetType = existingOpt.get().targetType();
		} else {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "targetType (ASN or SUBNET) is required.");
		}

		if (targetKey == null || targetKey.isBlank()) {
			if (existingOpt.isPresent()) {
				targetKey = existingOpt.get().targetKey();
			} else {
				return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "targetKey is required.");
			}
		}

		if (existingOpt.isEmpty()) {
			String lookupKey = targetKey.trim();
			if (targetType == AnnotationTargetType.SUBNET) {
				try {
					IpNetworkInfo netInfo = IpNetworkUtil.parse(lookupKey);
					if (netInfo != null && netInfo.subnetGroup() != null && !netInfo.subnetGroup().isBlank()) {
						lookupKey = netInfo.subnetGroup();
					}
				} catch (Exception ignored) {
				}
			}
			existingOpt = annotationService.getAnnotationByTarget(targetType, lookupKey);
		}

		AnnotationVerdict verdict = AnnotationVerdict.INFO;
		if (verdictRaw != null && !verdictRaw.isBlank()) {
			try {
				verdict = AnnotationVerdict.valueOf(verdictRaw.trim().toUpperCase(Locale.ROOT));
			} catch (IllegalArgumentException e) {
				return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST",
						"Invalid verdict '" + verdictRaw + "'.");
			}
		} else if (existingOpt.isPresent()) {
			verdict = existingOpt.get().verdict();
		}

		String cleanMarkdown = noteMarkdown != null ? noteMarkdown.trim() : "";

		if (CollectorAuthContext.isAiAgent()) {
			int minLen = properties.getSecurity().getAiGuardrails().getMinReasonLength();
			if (cleanMarkdown.length() < minLen) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "REASON_TOO_SHORT",
						"AI_AGENT notes must be at least " + minLen + " characters long.");
			}

			String aiName = currentActorLabel("ai");
			if (existingOpt.isPresent()) {
				NetworkAnnotation existing = existingOpt.get();
				boolean existingIsHuman = !isAiAuthoredNote(existing.noteMarkdown());
				if (existingIsHuman && !append) {
					return error(HttpStatus.CONFLICT, "HUMAN_NOTE_PROTECTED",
							"Existing human-authored annotation for " + existing.targetKey()
									+ " cannot be overwritten by AI_AGENT. Pass append=true to add an addendum.");
				}
				if (append || existingIsHuman) {
					// Preserve original human verdict if human-authored
					if (existingIsHuman) {
						verdict = existing.verdict();
					}
					String existingMd = existing.noteMarkdown() != null ? existing.noteMarkdown().trim() : "";
					String addendum = AI_NOTE_PREFIX + ": " + aiName + " @ " + Instant.now() + "**\n" + cleanMarkdown;
					cleanMarkdown = existingMd.isEmpty() ? addendum : existingMd + "\n\n---\n" + addendum;
					existingId = existing.id();
				} else {
					cleanMarkdown = AI_NOTE_PREFIX + ": " + aiName + " @ " + Instant.now() + "**\n" + cleanMarkdown;
					existingId = existing.id();
				}
			} else {
				cleanMarkdown = AI_NOTE_PREFIX + ": " + aiName + " @ " + Instant.now() + "**\n" + cleanMarkdown;
			}
		} else if (append && existingOpt.isPresent()) {
			String existingMd = existingOpt.get().noteMarkdown() != null ? existingOpt.get().noteMarkdown().trim() : "";
			if (!existingMd.isEmpty() && !cleanMarkdown.isEmpty()) {
				cleanMarkdown = existingMd + "\n\n---\n" + cleanMarkdown;
			}
			existingId = existingOpt.get().id();
		}

		try {
			NetworkAnnotation saved = annotationService.saveAnnotation(existingId, targetType, targetKey, verdict, cleanMarkdown);
			return ResponseEntity.ok(Map.of(
					"status", "SUCCESS",
					"actor", CollectorAuthContext.getEffectiveActor(defaultHumanActor()),
					"note", saved));
		} catch (IllegalArgumentException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", e.getMessage());
		} catch (IllegalStateException e) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN", e.getMessage());
		}
	}

	@DeleteMapping("/notes/{id}")
	public ResponseEntity<Map<String, Object>> deleteNote(@PathVariable long id) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"Operational writes are disabled in " + properties.getEffectiveMode() + " mode.");
		}
		if (CollectorAuthContext.isAiAgent()) {
			return error(HttpStatus.FORBIDDEN, "AI_DELETE_FORBIDDEN",
					"AI_AGENT tokens are not permitted to delete network annotations.");
		}
		boolean deleted = annotationService.deleteAnnotation(id);
		if (!deleted) {
			return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Annotation with id " + id + " was not found.");
		}
		return ResponseEntity.ok(Map.of(
				"status", "SUCCESS",
				"deletedId", id,
				"actor", CollectorAuthContext.getEffectiveActor(defaultHumanActor())));
	}

	// =========================================================================
	// Daily Reports API (/api/v1/reports)
	// =========================================================================

	@GetMapping("/reports")
	public ResponseEntity<Map<String, Object>> listReports(
			@RequestParam(defaultValue = "30") int limit) {
		int boundedLimit = Math.max(1, Math.min(365, limit));
		List<DailyReport> reports = dailyReportService.getRecentReports(boundedLimit);
		return ResponseEntity.ok(Map.of(
				"count", reports.size(),
				"reports", reports));
	}

	@GetMapping("/reports/{date}")
	public ResponseEntity<Map<String, Object>> getReport(@PathVariable String date) {
		String cleanDate;
		try {
			cleanDate = LocalDate.parse(date.trim()).toString();
		} catch (Exception e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid date format '" + date + "' (expected YYYY-MM-DD).");
		}
		Optional<DailyReport> report = dailyReportService.getReport(cleanDate);
		if (report.isEmpty()) {
			return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Daily report for " + cleanDate + " was not found.");
		}
		Optional<DailyReportNote> note = dailyReportService.getNote(cleanDate);
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("status", "OK");
		body.put("report", report.get());
		body.put("operatorNote", note.orElse(null));
		return ResponseEntity.ok(body);
	}

	@PostMapping("/reports/{date}/note")
	public ResponseEntity<Map<String, Object>> saveReportNote(
			@PathVariable String date,
			@RequestParam(required = false) Map<String, String> params,
			HttpServletRequest request) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"Operational writes are disabled in " + properties.getEffectiveMode() + " mode.");
		}
		String cleanDate;
		try {
			cleanDate = LocalDate.parse(date.trim()).toString();
		} catch (Exception e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid date format '" + date + "' (expected YYYY-MM-DD).");
		}

		Map<String, Object> payload;
		try {
			payload = extractPayload(request, params);
		} catch (IOException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid JSON payload: " + e.getMessage());
		}

		String noteMarkdown = asString(payload.get("noteMarkdown"));
		String cleanNote = noteMarkdown != null ? noteMarkdown.trim() : "";
		boolean append = asBoolean(payload.get("append"), false);

		if (cleanNote.isEmpty()) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "noteMarkdown must not be blank.");
		}

		if (CollectorAuthContext.isAiAgent()) {
			int minLen = properties.getSecurity().getAiGuardrails().getMinReasonLength();
			if (cleanNote.length() < minLen) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "REASON_TOO_SHORT",
						"AI_AGENT report notes must be at least " + minLen + " characters long.");
			}
			String aiEntry = AI_NOTE_PREFIX + ": " + currentActorLabel("ai") + " @ " + Instant.now() + "**\n" + cleanNote;
			Optional<DailyReportNote> existing = dailyReportService.getNote(cleanDate);
			if (existing.isPresent() && existing.get().hasContent()) {
				cleanNote = existing.get().noteMarkdown().trim() + "\n\n---\n" + aiEntry;
			} else {
				cleanNote = aiEntry;
			}
		} else if (append) {
			Optional<DailyReportNote> existing = dailyReportService.getNote(cleanDate);
			if (existing.isPresent() && existing.get().hasContent()) {
				cleanNote = existing.get().noteMarkdown().trim() + "\n\n---\n" + cleanNote;
			}
		}

		DailyReportNote saved = dailyReportService.saveNote(cleanDate, cleanNote);
		return ResponseEntity.ok(Map.of(
				"status", "SUCCESS",
				"actor", CollectorAuthContext.getEffectiveActor(defaultHumanActor()),
				"operatorNote", saved));
	}

	@DeleteMapping("/reports/{date}/note")
	public ResponseEntity<Map<String, Object>> deleteReportNote(@PathVariable String date) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"Operational writes are disabled in " + properties.getEffectiveMode() + " mode.");
		}
		if (CollectorAuthContext.isAiAgent()) {
			return error(HttpStatus.FORBIDDEN, "AI_DELETE_FORBIDDEN",
					"AI_AGENT tokens are not permitted to delete daily report notes.");
		}
		String cleanDate;
		try {
			cleanDate = LocalDate.parse(date.trim()).toString();
		} catch (Exception e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid date format '" + date + "' (expected YYYY-MM-DD).");
		}
		dailyReportService.deleteNote(cleanDate);
		return ResponseEntity.ok(Map.of(
				"status", "SUCCESS",
				"reportDate", cleanDate,
				"actor", CollectorAuthContext.getEffectiveActor(defaultHumanActor())));
	}

	@PostMapping("/reports/generate")
	public ResponseEntity<Map<String, Object>> generateReport(
			@RequestParam(required = false) Map<String, String> params,
			HttpServletRequest request) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"Report generation is disabled in " + properties.getEffectiveMode() + " mode.");
		}

		Map<String, Object> payload;
		try {
			payload = extractPayload(request, params);
		} catch (IOException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid JSON payload: " + e.getMessage());
		}

		String dateStr = asString(payload.get("date"));
		LocalDate targetDate;
		try {
			targetDate = (dateStr != null && !dateStr.isBlank())
					? LocalDate.parse(dateStr.trim())
					: LocalDate.now().minusDays(1);
		} catch (Exception e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST",
					"Invalid date format '" + dateStr + "' (expected YYYY-MM-DD).");
		}

		if (!dailyReportService.hasRawTelemetry(targetDate)) {
			Optional<DailyReport> existing = dailyReportService.getReport(targetDate.toString());
			if (existing.isPresent() && (existing.get().totalRequests() > 0 || existing.get().serverCount() > 0)) {
				return error(HttpStatus.CONFLICT, "TELEMETRY_EXPIRED",
						"Raw telemetry for " + targetDate + " has expired; existing archived report was preserved.");
			}
		}

		try {
			DailyReport generated = dailyReportService.generateDailyReport(targetDate);
			return ResponseEntity.ok(Map.of(
					"status", "SUCCESS",
					"actor", CollectorAuthContext.getEffectiveActor(defaultHumanActor()),
					"report", generated));
		} catch (IllegalStateException e) {
			return error(HttpStatus.CONFLICT, "CONFLICT", e.getMessage());
		}
	}

	// =========================================================================
	// Mitigation Operational & Guarded AI API (/api/v1/mitigation)
	// =========================================================================

	@PostMapping("/mitigation/preflight")
	public ResponseEntity<Map<String, Object>> preflightMitigation(
			@RequestParam(required = false) Map<String, String> params,
			HttpServletRequest request) {
		Map<String, Object> payload;
		try {
			payload = extractPayload(request, params);
		} catch (IOException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid JSON payload: " + e.getMessage());
		}

		List<String> inputs = extractCidrInputs(payload);
		if (inputs.isEmpty()) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "At least one 'cidr' or 'cidrs' input is required.");
		}

		MitigationService.PreflightCheckResult preflight = mitigationService.evaluatePreflight(inputs);
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("status", "OK");
		body.put("validCidrs", preflight.validCidrs());
		body.put("invalidInputs", preflight.invalidInputs());
		body.put("warnings", preflight.warnings());
		body.put("totalObservedRequests24h", preflight.totalObservedRequests24h());
		body.put("totalAuthenticatedRequests24h", preflight.totalAuthenticatedRequests24h());
		body.put("hasCriticalWarnings", preflight.hasCriticalWarnings());
		body.put("safeToProceedWithoutOverride", preflight.safeToProceedWithoutOverride());
		return ResponseEntity.ok(body);
	}

	@PostMapping("/mitigation/block")
	public ResponseEntity<Map<String, Object>> createBlock(
			@RequestParam(required = false) Map<String, String> params,
			HttpServletRequest request) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"Dynamic mitigation blocks are disabled in " + properties.getEffectiveMode() + " mode.");
		}

		Map<String, Object> payload;
		try {
			payload = extractPayload(request, params);
		} catch (IOException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid JSON payload: " + e.getMessage());
		}

		String rawCidr = asString(payload.get("cidr"));
		if (rawCidr == null || rawCidr.isBlank()) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "cidr is required.");
		}

		MitigationService.NormalizedCidr norm;
		try {
			norm = MitigationService.normalizeAndValidateCidr(rawCidr);
		} catch (IllegalArgumentException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", e.getMessage());
		}

		Integer requestedTtl = parseInteger(payload.get("ttlMinutes"));
		int ttlMinutes = (requestedTtl != null && requestedTtl > 0)
				? requestedTtl
				: properties.getDefaultMitigationTtlMinutes();
		String reason = asString(payload.get("reason"));
		String cleanReason = reason != null ? reason.trim() : "";
		boolean forceOverride = asBoolean(payload.get("forceOverride"), false);

		MitigationService.PreflightCheckResult preflight =
				mitigationService.evaluatePreflight(List.of(norm.canonicalCidr()));

		if (CollectorAuthContext.isAiAgent()) {
			CollectorProperties.AiGuardrailsConfig guardrails = properties.getSecurity().getAiGuardrails();

			if (cleanReason.length() < guardrails.getMinReasonLength()) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "REASON_TOO_SHORT",
						"AI_AGENT mitigation reason must be at least " + guardrails.getMinReasonLength() + " characters.");
			}
			if (ttlMinutes > guardrails.getMaxTtlMinutes()) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "TTL_EXCEEDS_AI_LIMIT",
						"Requested ttlMinutes (" + ttlMinutes + ") exceeds AI_AGENT max-ttl-minutes ("
								+ guardrails.getMaxTtlMinutes() + ").");
			}
			if (norm.ipVersion() == 4 && norm.prefixLength() < guardrails.getMinIpv4Prefix()) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "PREFIX_TOO_BROAD",
						"IPv4 prefix /" + norm.prefixLength() + " is broader than minimum AI_AGENT prefix /"
								+ guardrails.getMinIpv4Prefix() + ".");
			}
			if (norm.ipVersion() == 6 && norm.prefixLength() < guardrails.getMinIpv6Prefix()) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "PREFIX_TOO_BROAD",
						"IPv6 prefix /" + norm.prefixLength() + " is broader than minimum AI_AGENT prefix /"
								+ guardrails.getMinIpv6Prefix() + ".");
			}
			if (preflight.hasCriticalWarnings()) {
				Map<String, Object> body = new LinkedHashMap<>();
				body.put("status", "COLLATERAL_DAMAGE_RISK");
				body.put("message", "Refused AI_AGENT block due to critical preflight collateral-damage warnings (cannot be overridden).");
				body.put("warnings", preflight.warnings());
				return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(body);
			}
			int recentAiActions = mitigationService.countRecentAiBlockActions(Instant.now().minus(Duration.ofHours(1)));
			if (recentAiActions >= guardrails.getMaxBlocksPerHour()) {
				return error(HttpStatus.TOO_MANY_REQUESTS, "AI_RATE_LIMIT_EXCEEDED",
						"AI_AGENT hourly mitigation quota (" + guardrails.getMaxBlocksPerHour() + "/hour) exceeded.");
			}

			String actor = CollectorAuthContext.getEffectiveActor("AI_AGENT");
			MitigationRule saved = mitigationService.createOrUpdateBlock(
					norm.canonicalCidr(),
					ttlMinutes,
					cleanReason,
					MitigationRule.SOURCE_AI_AGENT,
					null,
					actor);
			return ResponseEntity.ok(Map.of(
					"status", "SUCCESS",
					"actor", actor,
					"rule", saved));
		}

		// Human OPERATOR or ADMIN path
		if (preflight.hasCriticalWarnings() && !forceOverride) {
			Map<String, Object> body = new LinkedHashMap<>();
			body.put("status", "PREFLIGHT_CONFIRMATION_REQUIRED");
			body.put("message", "Critical collateral-damage warnings detected. Re-submit with forceOverride=true to confirm.");
			body.put("warnings", preflight.warnings());
			return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
		}

		String actor = CollectorAuthContext.getEffectiveActor(defaultHumanActor());
		MitigationRule saved = mitigationService.createOrUpdateBlock(
				norm.canonicalCidr(),
				ttlMinutes,
				cleanReason.isEmpty() ? null : cleanReason,
				MitigationRule.SOURCE_MANUAL,
				null,
				actor);
		return ResponseEntity.ok(Map.of(
				"status", "SUCCESS",
				"actor", actor,
				"rule", saved));
	}

	@PostMapping("/mitigation/asn-block")
	public ResponseEntity<Map<String, Object>> blockAsnSubnets(
			@RequestParam(required = false) Map<String, String> params,
			HttpServletRequest request) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"ASN batch mitigation is disabled in " + properties.getEffectiveMode() + " mode.");
		}

		Map<String, Object> payload;
		try {
			payload = extractPayload(request, params);
		} catch (IOException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid JSON payload: " + e.getMessage());
		}

		Long asn = parseLong(payload.get("asn"));
		if (asn == null || asn <= 0) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Valid positive asn is required.");
		}
		Integer requestedHours = parseInteger(payload.get("hours"));
		int hours = (requestedHours != null && requestedHours > 0) ? Math.min(168, requestedHours) : 24;
		Integer requestedTtl = parseInteger(payload.get("ttlMinutes"));
		int ttlMinutes = (requestedTtl != null && requestedTtl > 0)
				? requestedTtl
				: properties.getDefaultMitigationTtlMinutes();
		String reason = asString(payload.get("reason"));
		String cleanReason = reason != null ? reason.trim() : "";

		if (CollectorAuthContext.isAiAgent()) {
			CollectorProperties.AiGuardrailsConfig guardrails = properties.getSecurity().getAiGuardrails();
			if (!guardrails.isAllowAsnBatchBlock()) {
				return error(HttpStatus.FORBIDDEN, "AI_ASN_BATCH_DISABLED",
						"AI_AGENT tokens are prohibited from ASN batch blocking by policy (allow-asn-batch-block=false).");
			}
			if (cleanReason.length() < guardrails.getMinReasonLength()) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "REASON_TOO_SHORT",
						"AI_AGENT ASN block reason must be at least " + guardrails.getMinReasonLength() + " characters.");
			}
			if (ttlMinutes > guardrails.getMaxTtlMinutes()) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "TTL_EXCEEDS_AI_LIMIT",
						"Requested ttlMinutes (" + ttlMinutes + ") exceeds AI_AGENT max-ttl-minutes ("
								+ guardrails.getMaxTtlMinutes() + ").");
			}
			int recentAiActions = mitigationService.countRecentAiBlockActions(Instant.now().minus(Duration.ofHours(1)));
			if (recentAiActions >= guardrails.getMaxBlocksPerHour()) {
				return error(HttpStatus.TOO_MANY_REQUESTS, "AI_RATE_LIMIT_EXCEEDED",
						"AI_AGENT hourly mitigation quota (" + guardrails.getMaxBlocksPerHour() + "/hour) exceeded.");
			}
		}

		String actor = CollectorAuthContext.getEffectiveActor(defaultHumanActor());
		List<MitigationRule> created = mitigationService.blockAsnSubnets(
				asn,
				hours,
				ttlMinutes,
				cleanReason.isEmpty() ? null : cleanReason,
				actor);
		return ResponseEntity.ok(Map.of(
				"status", "SUCCESS",
				"actor", actor,
				"asn", asn,
				"createdCount", created.size(),
				"rules", created));
	}

	@PostMapping("/mitigation/{id}/extend")
	public ResponseEntity<Map<String, Object>> extendRule(
			@PathVariable long id,
			@RequestParam(required = false) Map<String, String> params,
			HttpServletRequest request) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"Extending mitigation blocks is disabled in " + properties.getEffectiveMode() + " mode.");
		}

		Optional<MitigationRule> existingOpt = mitigationService.getRuleById(id);
		if (existingOpt.isEmpty()) {
			return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Mitigation rule " + id + " was not found.");
		}
		MitigationRule existing = existingOpt.get();

		Map<String, Object> payload;
		try {
			payload = extractPayload(request, params);
		} catch (IOException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid JSON payload: " + e.getMessage());
		}

		Integer requestedAdd = parseInteger(payload.get("additionalMinutes"));
		int additionalMinutes = (requestedAdd != null && requestedAdd > 0)
				? requestedAdd
				: properties.getDefaultMitigationTtlMinutes();

		if (CollectorAuthContext.isAiAgent()) {
			CollectorProperties.AiGuardrailsConfig guardrails = properties.getSecurity().getAiGuardrails();
			if (!MitigationRule.SOURCE_AI_AGENT.equalsIgnoreCase(existing.source())) {
				return error(HttpStatus.FORBIDDEN, "OWNERSHIP_VIOLATION",
						"AI_AGENT tokens may only extend rules created by AI_AGENT (rule source is " + existing.source() + ").");
			}
			Instant now = Instant.now();
			Instant base = (existing.expiresAt() != null
					&& existing.expiresAt().isAfter(now)
					&& MitigationRule.STATUS_ACTIVE.equals(existing.status()))
					? existing.expiresAt()
					: now;
			long resultingMinutes = Duration.between(now, base.plus(Duration.ofMinutes(additionalMinutes))).toMinutes();
			if (additionalMinutes > guardrails.getMaxTtlMinutes() || resultingMinutes > guardrails.getMaxTtlMinutes()) {
				return error(HttpStatus.UNPROCESSABLE_ENTITY, "TTL_EXCEEDS_AI_LIMIT",
						"Resulting TTL (" + resultingMinutes + " min) exceeds AI_AGENT max-ttl-minutes ("
								+ guardrails.getMaxTtlMinutes() + ").");
			}
			int recentAiActions = mitigationService.countRecentAiBlockActions(now.minus(Duration.ofHours(1)));
			if (recentAiActions >= guardrails.getMaxBlocksPerHour()) {
				return error(HttpStatus.TOO_MANY_REQUESTS, "AI_RATE_LIMIT_EXCEEDED",
						"AI_AGENT hourly mitigation quota (" + guardrails.getMaxBlocksPerHour() + "/hour) exceeded.");
			}
		}

		String actor = CollectorAuthContext.getEffectiveActor(defaultHumanActor());
		Optional<MitigationRule> updated = mitigationService.extendBlock(id, additionalMinutes, actor);
		if (updated.isEmpty()) {
			return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Mitigation rule " + id + " was not found.");
		}
		return ResponseEntity.ok(Map.of(
				"status", "SUCCESS",
				"actor", actor,
				"rule", updated.get()));
	}

	@PostMapping("/mitigation/{id}/revoke")
	public ResponseEntity<Map<String, Object>> revokeRule(
			@PathVariable long id,
			@RequestParam(required = false) Map<String, String> params,
			HttpServletRequest request) {
		if (!properties.canModifyOperationalData()) {
			return error(HttpStatus.FORBIDDEN, "FORBIDDEN",
					"Revoking mitigation blocks is disabled in " + properties.getEffectiveMode() + " mode.");
		}

		Optional<MitigationRule> existingOpt = mitigationService.getRuleById(id);
		if (existingOpt.isEmpty()) {
			return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Mitigation rule " + id + " was not found.");
		}
		MitigationRule existing = existingOpt.get();

		if (CollectorAuthContext.isAiAgent()
				&& !MitigationRule.SOURCE_AI_AGENT.equalsIgnoreCase(existing.source())) {
			return error(HttpStatus.FORBIDDEN, "OWNERSHIP_VIOLATION",
					"AI_AGENT tokens may only revoke rules created by AI_AGENT (rule source is " + existing.source() + ").");
		}

		Map<String, Object> payload;
		try {
			payload = extractPayload(request, params);
		} catch (IOException e) {
			return error(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid JSON payload: " + e.getMessage());
		}

		String reason = asString(payload.get("reason"));
		String actor = CollectorAuthContext.getEffectiveActor(defaultHumanActor());
		Optional<MitigationRule> revoked = mitigationService.revokeBlock(id, reason, actor);
		if (revoked.isEmpty()) {
			return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "Mitigation rule " + id + " was not found.");
		}
		return ResponseEntity.ok(Map.of(
				"status", "SUCCESS",
				"actor", actor,
				"rule", revoked.get()));
	}

	// =========================================================================
	// Helpers
	// =========================================================================

	private Map<String, Object> extractPayload(HttpServletRequest request, Map<String, String> params)
			throws IOException {
		Map<String, Object> merged = new LinkedHashMap<>();
		if (params != null) {
			params.forEach((k, v) -> {
				if (k != null && v != null && !"token".equals(k)) {
					merged.put(k, v);
				}
			});
		}
		String contentType = request.getContentType();
		if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json")) {
			String rawBody = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);
			if (rawBody != null && !rawBody.isBlank()) {
				Map<String, Object> jsonMap = objectMapper.readValue(rawBody, new TypeReference<>() {});
				if (jsonMap != null) {
					merged.putAll(jsonMap);
				}
			}
		}
		return merged;
	}

	private static List<String> extractCidrInputs(Map<String, Object> payload) {
		List<String> inputs = new ArrayList<>();
		Object cidrsObj = payload.get("cidrs");
		if (cidrsObj instanceof Collection<?> coll) {
			for (Object item : coll) {
				if (item != null && !item.toString().isBlank()) {
					inputs.add(item.toString().trim());
				}
			}
		} else if (cidrsObj instanceof String s && !s.isBlank()) {
			for (String line : s.split("[,\\r\\n]+")) {
				if (!line.isBlank()) {
					inputs.add(line.trim());
				}
			}
		}
		String single = asString(payload.get("cidr"));
		if (single != null && !single.isBlank()) {
			inputs.add(single.trim());
		}
		return inputs;
	}

	private static boolean isAiAuthoredNote(String noteMarkdown) {
		if (noteMarkdown == null) {
			return false;
		}
		String trimmed = noteMarkdown.trim();
		return trimmed.startsWith(AI_NOTE_PREFIX) || trimmed.startsWith("[AI_AGENT");
	}

	private String defaultHumanActor() {
		return properties.getMode().isOperator() ? "OPERATOR" : "ADMIN";
	}

	private static String currentActorLabel(String fallback) {
		CollectorAuthContext.AuthPrincipal principal = CollectorAuthContext.get();
		if (principal != null && principal.name() != null && !principal.name().isBlank()) {
			return principal.name();
		}
		return fallback;
	}

	private static String asString(Object val) {
		return val != null ? val.toString() : null;
	}

	private static Long parseLong(Object val) {
		if (val == null) {
			return null;
		}
		if (val instanceof Number n) {
			return n.longValue();
		}
		String s = val.toString().trim();
		if (s.isEmpty()) {
			return null;
		}
		try {
			return Long.parseLong(s);
		} catch (NumberFormatException e) {
			return null;
		}
	}

	private static Integer parseInteger(Object val) {
		if (val == null) {
			return null;
		}
		if (val instanceof Number n) {
			return n.intValue();
		}
		String s = val.toString().trim();
		if (s.isEmpty()) {
			return null;
		}
		try {
			return Integer.parseInt(s);
		} catch (NumberFormatException e) {
			return null;
		}
	}

	private static boolean asBoolean(Object val, boolean defaultValue) {
		if (val == null) {
			return defaultValue;
		}
		if (val instanceof Boolean b) {
			return b;
		}
		String s = val.toString().trim();
		if (s.isEmpty()) {
			return defaultValue;
		}
		return Boolean.parseBoolean(s);
	}

	private static ResponseEntity<Map<String, Object>> error(HttpStatus status, String code, String message) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("status", code);
		body.put("message", message);
		return ResponseEntity.status(status).body(body);
	}
}
