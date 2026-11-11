package org.henbru.antidos.collector.mitigation;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.notification.AlertNotificationService;
import org.henbru.antidos.collector.storage.SystemSettingsRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Autonomous, deterministic mitigation engine.
 * <p>
 * Periodically scans recent telemetry for distributed horizontal carpet attacks and abusive clusters.
 * Enforces strict safety guardrails (0 authenticated requests, returning visitor ratio <= maxReturningRatioPct,
 * crawler protection, circuit breaker cap), handles dry-run simulation vs. live block activation,
 * and manages the lifecycle of dynamic rules (auto-extension for persistent attackers).
 */
@Service
public class AutoMitigationService {

	private static final Logger log = LoggerFactory.getLogger(AutoMitigationService.class);

	// System settings keys
	public static final String KEY_ENABLED = "mitigation.auto.enabled";
	public static final String KEY_DRY_RUN = "mitigation.auto.dry_run";
	public static final String KEY_CARPET_MIN_SUBNETS = "mitigation.auto.carpet_min_subnets";
	public static final String KEY_CARPET_MIN_REQUESTS = "mitigation.auto.carpet_min_requests";
	public static final String KEY_CARPET_WINDOW_HOURS = "mitigation.auto.carpet_window_hours";
	public static final String KEY_PROTECTED_ASNS = "mitigation.auto.protected_asns";
	public static final String KEY_MAX_RETURNING_PCT = "mitigation.auto.max_returning_ratio_pct";
	public static final String KEY_MAX_ACTIVE_RULES = "mitigation.auto.max_active_rules";
	public static final String KEY_DEFAULT_TTL_MINUTES = "mitigation.auto.default_ttl_minutes";
	public static final String KEY_AUTO_EXTEND = "mitigation.auto.auto_extend_persistent";
	public static final String KEY_MAX_EXTENSION_HOURS = "mitigation.auto.max_extension_hours";

	private final CollectorProperties properties;
	private final SystemSettingsRepository settingsRepository;
	private final MitigationService mitigationService;
	private final AlertNotificationService notificationService;
	private final JdbcTemplate jdbcTemplate;

	private final AtomicBoolean scanRunning = new AtomicBoolean(false);

	@Autowired
	public AutoMitigationService(
			CollectorProperties properties,
			SystemSettingsRepository settingsRepository,
			MitigationService mitigationService,
			@Autowired(required = false) AlertNotificationService notificationService,
			JdbcTemplate jdbcTemplate
	) {
		this.properties = properties;
		this.settingsRepository = settingsRepository;
		this.mitigationService = mitigationService;
		this.notificationService = notificationService;
		this.jdbcTemplate = jdbcTemplate;
	}

	public AutoMitigationService(
			CollectorProperties properties,
			SystemSettingsRepository settingsRepository,
			MitigationService mitigationService,
			JdbcTemplate jdbcTemplate
	) {
		this(properties, settingsRepository, mitigationService, null, jdbcTemplate);
	}

	/**
	 * Effective configuration combining database overrides with static YAML defaults.
	 */
	public record EffectiveAutoSettings(
			boolean enabled,
			boolean dryRun,
			int carpetMinSubnets,
			long carpetMinRequests,
			int carpetWindowHours,
			String protectedAsns,
			double maxReturningRatioPct,
			int maxActiveRules,
			int defaultTtlMinutes,
			boolean autoExtendPersistent,
			int maxExtensionHours,
			boolean hasDatabaseOverrides
	) {
		public boolean isEnabled() { return enabled; }
		public boolean isDryRun() { return dryRun; }
		public int getCarpetMinSubnets() { return carpetMinSubnets; }
		public long getCarpetMinRequests() { return carpetMinRequests; }
		public int getCarpetWindowHours() { return carpetWindowHours; }
		public String getProtectedAsns() { return protectedAsns; }
		public Set<Long> getProtectedAsnSet() { return CollectorProperties.AutoMitigationConfig.parseAsnSet(protectedAsns); }
		public double getMaxReturningRatioPct() { return maxReturningRatioPct; }
		public int getMaxActiveRules() { return maxActiveRules; }
		public int getDefaultTtlMinutes() { return defaultTtlMinutes; }
		public boolean isAutoExtendPersistent() { return autoExtendPersistent; }
		public int getMaxExtensionHours() { return maxExtensionHours; }
		public boolean isHasDatabaseOverrides() { return hasDatabaseOverrides; }
	}

	public EffectiveAutoSettings getEffectiveSettings() {
		CollectorProperties.AutoMitigationConfig yaml = properties.getAutoMitigation();

		Optional<Boolean> dbEnabled = settingsRepository.getBoolean(KEY_ENABLED);
		Optional<Boolean> dbDryRun = settingsRepository.getBoolean(KEY_DRY_RUN);
		Optional<Integer> dbMinSubnets = settingsRepository.getInt(KEY_CARPET_MIN_SUBNETS);
		Optional<Long> dbMinReqs = settingsRepository.getLong(KEY_CARPET_MIN_REQUESTS);
		Optional<Integer> dbWindowHours = settingsRepository.getInt(KEY_CARPET_WINDOW_HOURS);
		Optional<String> dbProtectedAsns = settingsRepository.getString(KEY_PROTECTED_ASNS);
		Optional<Double> dbMaxReturnPct = settingsRepository.getDouble(KEY_MAX_RETURNING_PCT);
		Optional<Integer> dbMaxActive = settingsRepository.getInt(KEY_MAX_ACTIVE_RULES);
		Optional<Integer> dbTtl = settingsRepository.getInt(KEY_DEFAULT_TTL_MINUTES);
		Optional<Boolean> dbExtend = settingsRepository.getBoolean(KEY_AUTO_EXTEND);
		Optional<Integer> dbMaxExtHours = settingsRepository.getInt(KEY_MAX_EXTENSION_HOURS);

		boolean hasDbOverrides = dbEnabled.isPresent() || dbDryRun.isPresent() || dbMinSubnets.isPresent()
				|| dbMinReqs.isPresent() || dbWindowHours.isPresent() || dbProtectedAsns.isPresent()
				|| dbMaxReturnPct.isPresent() || dbMaxActive.isPresent()
				|| dbTtl.isPresent() || dbExtend.isPresent() || dbMaxExtHours.isPresent();

		return new EffectiveAutoSettings(
				dbEnabled.orElse(yaml.isEnabled()),
				dbDryRun.orElse(yaml.isDryRun()),
				dbMinSubnets.orElse(yaml.getCarpetMinSubnets()),
				dbMinReqs.orElse(yaml.getCarpetMinRequests()),
				dbWindowHours.orElse(yaml.getCarpetWindowHours()),
				dbProtectedAsns.orElse(yaml.getProtectedAsns()),
				dbMaxReturnPct.orElse(yaml.getMaxReturningRatioPct()),
				dbMaxActive.orElse(yaml.getMaxActiveRules()),
				dbTtl.orElse(yaml.getDefaultTtlMinutes()),
				dbExtend.orElse(yaml.isAutoExtendPersistent()),
				dbMaxExtHours.orElse(yaml.getMaxExtensionHours()),
				hasDbOverrides
		);
	}

	public void updateSettings(
			boolean enabled,
			boolean dryRun,
			int carpetMinSubnets,
			long carpetMinRequests,
			int carpetWindowHours,
			String protectedAsns,
			double maxReturningRatioPct,
			int maxActiveRules,
			int defaultTtlMinutes,
			boolean autoExtendPersistent,
			int maxExtensionHours,
			String updatedBy
	) {
		settingsRepository.setSetting(KEY_ENABLED, String.valueOf(enabled), "Auto-mitigation master switch", updatedBy);
		settingsRepository.setSetting(KEY_DRY_RUN, String.valueOf(dryRun), "Auto-mitigation dry-run simulation mode", updatedBy);
		settingsRepository.setSetting(KEY_CARPET_MIN_SUBNETS, String.valueOf(Math.max(1, carpetMinSubnets)), "Min subnets per ASN for carpet attack detection", updatedBy);
		settingsRepository.setSetting(KEY_CARPET_MIN_REQUESTS, String.valueOf(Math.max(1L, carpetMinRequests)), "Min aggregate requests for carpet attack detection", updatedBy);
		settingsRepository.setSetting(KEY_CARPET_WINDOW_HOURS, String.valueOf(Math.max(1, Math.min(720, carpetWindowHours))), "Lookback window in hours for carpet attack detection", updatedBy);
		settingsRepository.setSetting(KEY_PROTECTED_ASNS, protectedAsns != null ? protectedAsns.trim() : "", "Protected ASNs exempt from auto-mitigation", updatedBy);
		settingsRepository.setSetting(KEY_MAX_RETURNING_PCT, String.valueOf(Math.max(0.0, Math.min(100.0, maxReturningRatioPct))), "Max returning visitor ratio allowed for auto-block", updatedBy);
		settingsRepository.setSetting(KEY_MAX_ACTIVE_RULES, String.valueOf(Math.max(1, maxActiveRules)), "Circuit-breaker max active auto rules", updatedBy);
		settingsRepository.setSetting(KEY_DEFAULT_TTL_MINUTES, String.valueOf(Math.max(1, defaultTtlMinutes)), "Default TTL minutes for auto rules", updatedBy);
		settingsRepository.setSetting(KEY_AUTO_EXTEND, String.valueOf(autoExtendPersistent), "Auto-extend persistent attackers", updatedBy);
		settingsRepository.setSetting(KEY_MAX_EXTENSION_HOURS, String.valueOf(Math.max(1, maxExtensionHours)), "Max extension hours for auto rules", updatedBy);
		log.info("Auto-mitigation settings updated by '{}': enabled={}, dryRun={}, carpetMinSubnets={}, windowHours={}, protectedAsns='{}'",
				updatedBy, enabled, dryRun, carpetMinSubnets, carpetWindowHours, protectedAsns);
	}

	public void resetToDefaults(String updatedBy) {
		settingsRepository.deleteSetting(KEY_ENABLED);
		settingsRepository.deleteSetting(KEY_DRY_RUN);
		settingsRepository.deleteSetting(KEY_CARPET_MIN_SUBNETS);
		settingsRepository.deleteSetting(KEY_CARPET_MIN_REQUESTS);
		settingsRepository.deleteSetting(KEY_CARPET_WINDOW_HOURS);
		settingsRepository.deleteSetting(KEY_PROTECTED_ASNS);
		settingsRepository.deleteSetting(KEY_MAX_RETURNING_PCT);
		settingsRepository.deleteSetting(KEY_MAX_ACTIVE_RULES);
		settingsRepository.deleteSetting(KEY_DEFAULT_TTL_MINUTES);
		settingsRepository.deleteSetting(KEY_AUTO_EXTEND);
		settingsRepository.deleteSetting(KEY_MAX_EXTENSION_HOURS);
		log.info("Auto-mitigation settings reset to application.yaml defaults by '{}'", updatedBy);
	}

	public record CarpetAttackCandidate(
			long asn,
			String asOrg,
			int activeSubnets,
			long totalRequests,
			long returningRequests,
			double returningRatioPct,
			List<String> eligibleSubnets
	) {}

	/**
	 * Scheduled scan running every 2 minutes across recent telemetry.
	 */
	@Scheduled(fixedDelay = 120_000, initialDelay = 30_000)
	public void scheduledAutonomousEvaluation() {
		EffectiveAutoSettings config = getEffectiveSettings();
		if (!config.enabled()) {
			return;
		}

		if (!scanRunning.compareAndSet(false, true)) {
			log.debug("Auto-mitigation evaluation already in progress, skipping tick");
			return;
		}

		try {
			evaluateAndEnforce(config);
			if (config.autoExtendPersistent()) {
				evaluateExtensions(config);
			}
		} catch (Exception e) {
			log.error("Error during auto-mitigation evaluation: {}", e.getMessage(), e);
		} finally {
			scanRunning.set(false);
		}
	}

	/**
	 * Evaluates active carpet attack candidates and enforces auto-blocks or dry-run audit entries.
	 */
	public List<CarpetAttackCandidate> evaluateAndEnforce(EffectiveAutoSettings config) {
		Instant now = Instant.now();
		List<CarpetAttackCandidate> candidates = findCarpetAttackCandidates(config, config.carpetWindowHours());

		if (candidates.isEmpty()) {
			return List.of();
		}

		List<MitigationRule> activeRules = mitigationService.getActiveRules();
		long currentAutoCount = activeRules.stream()
				.filter(r -> MitigationRule.SOURCE_AUTO_CARPET.equalsIgnoreCase(r.source())
						|| MitigationRule.SOURCE_AUTO_RULE.equalsIgnoreCase(r.source()))
				.count();

		Set<Long> protectedAsns = config.getProtectedAsnSet();

		for (CarpetAttackCandidate c : candidates) {
			if (protectedAsns.contains(c.asn())) {
				log.info("[AUTO-SKIP] ASN {} ({}) is on the protected ASNs list. Skipping autonomous block.", c.asn(), c.asOrg());
				mitigationService.recordAudit(null, "ASN-" + c.asn(), "AUTO_SKIPPED_PROTECTED_ASN",
						"Skipped autonomous block for ASN " + c.asn() + " (" + (c.asOrg() != null ? c.asOrg() : "Unknown")
								+ ") because it is on the protected ASNs list (" + config.protectedAsns() + ").",
						0, "AUTO_ENGINE");
				continue;
			}

			if (currentAutoCount >= config.maxActiveRules()) {
				log.warn("Auto-mitigation circuit breaker reached ({} >= {}). Skipping ASN {} ({} subnets)",
						currentAutoCount, config.maxActiveRules(), c.asn(), c.activeSubnets());
				mitigationService.recordAudit(null, "ASN-" + c.asn(), "AUTO_CIRCUIT_BREAKER",
						"Circuit breaker limit of " + config.maxActiveRules() + " active auto rules reached. Skipped ASN " + c.asn() + " (" + c.activeSubnets() + " subnets).",
						0, "AUTO_ENGINE");
				if (notificationService != null) {
					notificationService.sendCircuitBreakerAlert(currentAutoCount, config.maxActiveRules(), c.asn(), c.activeSubnets());
				}
				break;
			}

			// Filter out subnets that already have an active mitigation rule
			List<String> newSubnetsToBlock = c.eligibleSubnets().stream()
					.filter(sub -> activeRules.stream().noneMatch(ar -> ar.cidr().equalsIgnoreCase(sub)))
					.toList();

			if (newSubnetsToBlock.isEmpty()) {
				continue;
			}

			// Respect circuit breaker limit for the batch size
			int allowedToBlock = (int) Math.min(newSubnetsToBlock.size(), config.maxActiveRules() - currentAutoCount);
			List<String> targetSubnets = newSubnetsToBlock.subList(0, allowedToBlock);
			String batchId = "AUTO-ASN-" + c.asn() + "-" + (now.toEpochMilli() / 1000L);
			String reason = "Carpet attack from ASN " + c.asn() + " (" + (c.asOrg() != null ? c.asOrg() : "Unknown")
					+ "): " + c.activeSubnets() + " subnets, " + c.totalRequests() + " reqs, returning ratio "
					+ String.format("%.2f%%", c.returningRatioPct());

			if (config.dryRun()) {
				log.info("[DRY-RUN] Would block {} subnet(s) for ASN {} (Batch: {}, TTL: {}m). Reason: {}",
						targetSubnets.size(), c.asn(), batchId, config.defaultTtlMinutes(), reason);
				mitigationService.recordAudit(null, "ASN-" + c.asn(), "AUTO_WOULD_BLOCK",
						"[DRY-RUN SIMULATION] Would block " + targetSubnets.size() + " subnets ("
								+ String.join(", ", targetSubnets) + "). " + reason,
						config.defaultTtlMinutes() * 60, "AUTO_ENGINE");
				if (notificationService != null) {
					notificationService.sendDryRunAlert(c.asn(), c.asOrg(), targetSubnets, batchId, config.defaultTtlMinutes(), reason);
				}
			} else {
				log.warn("[AUTO-BLOCK] Blocking {} subnets for ASN {} (Batch: {}, TTL: {}m). Reason: {}",
						targetSubnets.size(), c.asn(), batchId, config.defaultTtlMinutes(), reason);
				List<MitigationRule> created = mitigationService.createBatchBlocks(
						targetSubnets,
						config.defaultTtlMinutes(),
						reason,
						MitigationRule.SOURCE_AUTO_CARPET,
						batchId,
						"AUTO_ENGINE"
				);
				currentAutoCount += created.size();
				if (notificationService != null) {
					notificationService.sendAutoBlockAlert(c.asn(), c.asOrg(), targetSubnets, batchId, config.defaultTtlMinutes(), reason);
				}
			}
		}

		return candidates;
	}

	/**
	 * Detects ASNs distributing traffic across multiple unauthenticated subnets with very low returning visitor ratios.
	 */
	public List<CarpetAttackCandidate> findCarpetAttackCandidates(EffectiveAutoSettings config, int hours) {
		int safeHours = Math.max(1, Math.min(hours, 720));
		Instant cutoff = Instant.now().minus(Duration.ofHours(safeHours));

		String sql = """
				SELECT
				    asn,
				    MAX(as_org) AS as_org,
				    COUNT(DISTINCT subnet_group) AS active_subnets,
				    SUM(total_requests) AS total_requests,
				    SUM(returning_requests) AS total_returning,
				    SUM(authenticated_requests) AS total_authenticated
				FROM client_subnet_rollups
				WHERE bucket_start >= ?
				  AND asn IS NOT NULL
				  AND asn > 0
				  AND (client_type IS NULL OR client_type NOT IN ('SEARCH_ENGINE', 'AI_CRAWLER', 'PRIVATE_NETWORK', 'INTERNAL_NETWORK'))
				GROUP BY asn
				HAVING COUNT(DISTINCT subnet_group) >= ?
				   AND SUM(total_requests) >= ?
				   AND SUM(authenticated_requests) = 0
				ORDER BY total_requests DESC
				""";

		List<CarpetAttackCandidate> candidates = new ArrayList<>();

		jdbcTemplate.query(sql, rs -> {
			long asn = rs.getLong("asn");
			String rawAsOrg = rs.getString("as_org");
			String asOrg = resolveAsnOrg(asn, rawAsOrg);
			int activeSubnets = rs.getInt("active_subnets");
			long totalReq = rs.getLong("total_requests");
			long returningReq = rs.getLong("total_returning");
			double returningPct = totalReq > 0 ? (returningReq * 100.0 / totalReq) : 0.0;

			if (returningPct <= config.maxReturningRatioPct()) {
				// Query individual candidate subnets that strictly have 0 authenticated requests
				// and returning ratio <= maxReturningRatioPct
				List<String> eligibleSubnets = findEligibleSubnetsForAsn(asn, safeHours, config.maxReturningRatioPct());
				if (eligibleSubnets.size() >= config.carpetMinSubnets()) {
					candidates.add(new CarpetAttackCandidate(
							asn, asOrg, activeSubnets, totalReq, returningReq, returningPct, eligibleSubnets
					));
				}
			}
		}, java.sql.Timestamp.from(cutoff), config.carpetMinSubnets(), config.carpetMinRequests());

		return candidates;
	}

	private List<String> findEligibleSubnetsForAsn(long asn, int hours, double maxReturningPct) {
		Instant cutoff = Instant.now().minus(Duration.ofHours(hours));
		String sql = """
				SELECT
				    subnet_group,
				    SUM(total_requests) AS sub_total,
				    SUM(returning_requests) AS sub_returning,
				    SUM(authenticated_requests) AS sub_authenticated
				FROM client_subnet_rollups
				WHERE bucket_start >= ?
				  AND asn = ?
				  AND (client_type IS NULL OR client_type NOT IN ('SEARCH_ENGINE', 'AI_CRAWLER', 'PRIVATE_NETWORK', 'INTERNAL_NETWORK'))
				GROUP BY subnet_group
				HAVING SUM(authenticated_requests) = 0
				ORDER BY sub_total DESC
				""";

		List<String> result = new ArrayList<>();
		jdbcTemplate.query(sql, rs -> {
			String sub = rs.getString("subnet_group");
			long total = rs.getLong("sub_total");
			long returning = rs.getLong("sub_returning");
			double subReturnPct = total > 0 ? (returning * 100.0 / total) : 0.0;

			// Strict safety checks: returning ratio <= threshold, not a search engine, not private
			if (subReturnPct <= maxReturningPct && sub != null && !sub.isBlank()) {
				MitigationService.PreflightCheckResult pre = mitigationService.evaluatePreflight(List.of(sub));
				if (pre.safeToProceedWithoutOverride()) {
					result.add(sub);
				}
			}
		}, java.sql.Timestamp.from(cutoff), asn);

		return result;
	}

	private String resolveAsnOrg(long asn, String fallbackOrg) {
		try {
			List<String> list = jdbcTemplate.query(
					"SELECT as_org FROM asn_info WHERE asn = ? AND as_org IS NOT NULL AND as_org != '' LIMIT 1",
					(rs, rowNum) -> rs.getString("as_org"),
					asn
			);
			if (!list.isEmpty() && list.getFirst() != null && !list.getFirst().isBlank()) {
				return list.getFirst();
			}
		} catch (Exception ignored) {}
		if (asn == 8075L) return "Microsoft Azure";
		if (asn == 16509L || asn == 14618L) return "Amazon AWS";
		if (asn == 15169L) return "Google Cloud";
		if (asn == 13335L) return "Cloudflare";
		return (fallbackOrg != null && !fallbackOrg.isBlank()) ? fallbackOrg : "AS" + asn;
	}

	/**
	 * Automatically extends active rules for persistent attackers if enabled.
	 */
	public int evaluateExtensions(EffectiveAutoSettings config) {
		Instant now = Instant.now();
		mitigationService.refreshDeterrenceMetrics();
		List<MitigationRule> activeRules = mitigationService.getActiveRules();

		int extendedCount = 0;
		for (MitigationRule r : activeRules) {
			// Only auto-extend rules created by AUTO_CARPET / AUTO_RULE or explicitly marked for auto-lifecycle
			if (!MitigationRule.SOURCE_AUTO_CARPET.equalsIgnoreCase(r.source())
					&& !MitigationRule.SOURCE_AUTO_RULE.equalsIgnoreCase(r.source())) {
				continue;
			}

			// If rule is PERSISTENT and has <= 15 minutes left
			if (MitigationRule.DETERRENCE_PERSISTENT.equalsIgnoreCase(r.deterrenceState()) && r.remainingMinutes(now) <= 15) {
				long totalLifetimeMinutes = Duration.between(r.createdAt(), r.expiresAt()).toMinutes();
				long maxLifetimeMinutes = (long) config.maxExtensionHours() * 60L;

				if (totalLifetimeMinutes < maxLifetimeMinutes) {
					int addMin = Math.min(60, (int) (maxLifetimeMinutes - totalLifetimeMinutes));
					if (addMin > 0) {
						if (config.dryRun()) {
							log.info("[DRY-RUN] Would auto-extend rule #{} ({}) by +{}m (Attacker still PERSISTENT)",
									r.id(), r.cidr(), addMin);
							mitigationService.recordAudit(r.id(), r.cidr(), "AUTO_WOULD_EXTEND",
									"[DRY-RUN SIMULATION] Would auto-extend persistent rule by +" + addMin + "m.",
									addMin * 60, "AUTO_ENGINE");
						} else {
							mitigationService.extendBlock(r.id(), addMin, "AUTO_ENGINE");
							log.warn("[AUTO-EXTEND] Extended rule #{} ({}) by +{}m due to persistent attacker traffic",
									r.id(), r.cidr(), addMin);
							extendedCount++;
						}
					}
				} else {
					log.info("Rule #{} ({}) reached max extension cap of {}h. Allowing TTL to elapse naturally.",
							r.id(), r.cidr(), config.maxExtensionHours());
				}
			}
		}
		return extendedCount;
	}
}
