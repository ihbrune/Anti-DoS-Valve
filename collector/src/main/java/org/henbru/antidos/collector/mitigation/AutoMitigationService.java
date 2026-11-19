package org.henbru.antidos.collector.mitigation;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.CarpetRadarEntry;
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
 * Enforces strict safety guardrails (0 authenticated requests on blocked subnets, configurable ASN-level auth tolerance,
 * returning visitor ratio <= maxReturningRatioPct, crawler protection, circuit breaker cap), handles dry-run simulation
 * vs. live block activation, and manages the lifecycle of dynamic rules (auto-extension for persistent attackers).
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
	public static final String KEY_MAX_AUTHENTICATED_REQUESTS = "mitigation.auto.max_authenticated_requests";
	public static final String KEY_CARPET_MIN_REQUESTS_PER_SUBNET = "mitigation.auto.carpet_min_requests_per_subnet";
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

	private static final long RADAR_CACHE_TTL_MS = 60_000L;
	private volatile List<CarpetRadarEntry> cachedRadar;
	private volatile int cachedRadarHours = -1;
	private volatile long cachedRadarAtMillis = 0L;

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
			long maxAuthenticatedRequests,
			long carpetMinRequestsPerSubnet,
			int maxActiveRules,
			int defaultTtlMinutes,
			boolean autoExtendPersistent,
			int maxExtensionHours,
			boolean hasDatabaseOverrides
	) {
		/** Backwards-compatible constructor without the per-subnet volume filter (disabled = 0). */
		public EffectiveAutoSettings(
				boolean enabled,
				boolean dryRun,
				int carpetMinSubnets,
				long carpetMinRequests,
				int carpetWindowHours,
				String protectedAsns,
				double maxReturningRatioPct,
				long maxAuthenticatedRequests,
				int maxActiveRules,
				int defaultTtlMinutes,
				boolean autoExtendPersistent,
				int maxExtensionHours,
				boolean hasDatabaseOverrides
		) {
			this(enabled, dryRun, carpetMinSubnets, carpetMinRequests, carpetWindowHours,
					protectedAsns, maxReturningRatioPct, maxAuthenticatedRequests, 0L, maxActiveRules,
					defaultTtlMinutes, autoExtendPersistent, maxExtensionHours, hasDatabaseOverrides);
		}

		public EffectiveAutoSettings(
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
			this(enabled, dryRun, carpetMinSubnets, carpetMinRequests, carpetWindowHours,
					protectedAsns, maxReturningRatioPct, 0L, 0L, maxActiveRules, defaultTtlMinutes,
					autoExtendPersistent, maxExtensionHours, hasDatabaseOverrides);
		}

		public boolean isEnabled() { return enabled; }
		public boolean isDryRun() { return dryRun; }
		public int getCarpetMinSubnets() { return carpetMinSubnets; }
		public long getCarpetMinRequests() { return carpetMinRequests; }
		public int getCarpetWindowHours() { return carpetWindowHours; }
		public String getProtectedAsns() { return protectedAsns; }
		public Set<Long> getProtectedAsnSet() { return CollectorProperties.AutoMitigationConfig.parseAsnSet(protectedAsns); }
		public double getMaxReturningRatioPct() { return maxReturningRatioPct; }
		public long getMaxAuthenticatedRequests() { return maxAuthenticatedRequests; }
		public long getCarpetMinRequestsPerSubnet() { return carpetMinRequestsPerSubnet; }
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
		Optional<Long> dbMaxAuthReqs = settingsRepository.getLong(KEY_MAX_AUTHENTICATED_REQUESTS);
		Optional<Long> dbMinReqsPerSubnet = settingsRepository.getLong(KEY_CARPET_MIN_REQUESTS_PER_SUBNET);
		Optional<Integer> dbMaxActive = settingsRepository.getInt(KEY_MAX_ACTIVE_RULES);
		Optional<Integer> dbTtl = settingsRepository.getInt(KEY_DEFAULT_TTL_MINUTES);
		Optional<Boolean> dbExtend = settingsRepository.getBoolean(KEY_AUTO_EXTEND);
		Optional<Integer> dbMaxExtHours = settingsRepository.getInt(KEY_MAX_EXTENSION_HOURS);

		boolean hasDbOverrides = dbEnabled.isPresent() || dbDryRun.isPresent() || dbMinSubnets.isPresent()
				|| dbMinReqs.isPresent() || dbWindowHours.isPresent() || dbProtectedAsns.isPresent()
				|| dbMaxReturnPct.isPresent() || dbMaxAuthReqs.isPresent() || dbMinReqsPerSubnet.isPresent()
				|| dbMaxActive.isPresent() || dbTtl.isPresent() || dbExtend.isPresent() || dbMaxExtHours.isPresent();

		return new EffectiveAutoSettings(
				dbEnabled.orElse(yaml.isEnabled()),
				dbDryRun.orElse(yaml.isDryRun()),
				dbMinSubnets.orElse(yaml.getCarpetMinSubnets()),
				dbMinReqs.orElse(yaml.getCarpetMinRequests()),
				dbWindowHours.orElse(yaml.getCarpetWindowHours()),
				dbProtectedAsns.orElse(yaml.getProtectedAsns()),
				dbMaxReturnPct.orElse(yaml.getMaxReturningRatioPct()),
				dbMaxAuthReqs.orElse(yaml.getMaxAuthenticatedRequests()),
				dbMinReqsPerSubnet.orElse(yaml.getCarpetMinRequestsPerSubnet()),
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
		updateSettings(enabled, dryRun, carpetMinSubnets, carpetMinRequests, carpetWindowHours,
				protectedAsns, maxReturningRatioPct, 0L, maxActiveRules, defaultTtlMinutes,
				autoExtendPersistent, maxExtensionHours, updatedBy);
	}

	public void updateSettings(
			boolean enabled,
			boolean dryRun,
			int carpetMinSubnets,
			long carpetMinRequests,
			int carpetWindowHours,
			String protectedAsns,
			double maxReturningRatioPct,
			long maxAuthenticatedRequests,
			int maxActiveRules,
			int defaultTtlMinutes,
			boolean autoExtendPersistent,
			int maxExtensionHours,
			String updatedBy
	) {
		updateSettings(enabled, dryRun, carpetMinSubnets, carpetMinRequests, carpetWindowHours,
				protectedAsns, maxReturningRatioPct, maxAuthenticatedRequests,
				getEffectiveSettings().carpetMinRequestsPerSubnet(), maxActiveRules, defaultTtlMinutes,
				autoExtendPersistent, maxExtensionHours, updatedBy);
	}

	public void updateSettings(
			boolean enabled,
			boolean dryRun,
			int carpetMinSubnets,
			long carpetMinRequests,
			int carpetWindowHours,
			String protectedAsns,
			double maxReturningRatioPct,
			long maxAuthenticatedRequests,
			long carpetMinRequestsPerSubnet,
			int maxActiveRules,
			int defaultTtlMinutes,
			boolean autoExtendPersistent,
			int maxExtensionHours,
			String updatedBy
	) {
		if (!properties.getMode().isBackgroundProcessingEnabled()) {
			throw new IllegalStateException("Auto-mitigation settings cannot be modified in " + properties.getMode() + " mode.");
		}
		long safeMaxAuthRequests = Math.max(0L, maxAuthenticatedRequests);
		long safeMinReqsPerSubnet = Math.max(0L, carpetMinRequestsPerSubnet);
		settingsRepository.setSetting(KEY_ENABLED, String.valueOf(enabled), "Auto-mitigation master switch", updatedBy);
		settingsRepository.setSetting(KEY_DRY_RUN, String.valueOf(dryRun), "Auto-mitigation dry-run simulation mode", updatedBy);
		settingsRepository.setSetting(KEY_CARPET_MIN_SUBNETS, String.valueOf(Math.max(1, carpetMinSubnets)), "Min subnets per ASN for carpet attack detection", updatedBy);
		settingsRepository.setSetting(KEY_CARPET_MIN_REQUESTS, String.valueOf(Math.max(1L, carpetMinRequests)), "Min aggregate requests for carpet attack detection", updatedBy);
		settingsRepository.setSetting(KEY_CARPET_WINDOW_HOURS, String.valueOf(Math.max(1, Math.min(720, carpetWindowHours))), "Lookback window in hours for carpet attack detection", updatedBy);
		settingsRepository.setSetting(KEY_PROTECTED_ASNS, protectedAsns != null ? protectedAsns.trim() : "", "Protected ASNs exempt from auto-mitigation", updatedBy);
		settingsRepository.setSetting(KEY_MAX_RETURNING_PCT, String.valueOf(Math.max(0.0, Math.min(100.0, maxReturningRatioPct))), "Max returning visitor ratio allowed for auto-block", updatedBy);
		settingsRepository.setSetting(KEY_MAX_AUTHENTICATED_REQUESTS, String.valueOf(safeMaxAuthRequests), "Max authenticated requests per ASN allowed for auto-block candidate", updatedBy);
		settingsRepository.setSetting(KEY_CARPET_MIN_REQUESTS_PER_SUBNET, String.valueOf(safeMinReqsPerSubnet), "Min requests a single subnet must produce in the lookback window to be auto-blocked", updatedBy);
		settingsRepository.setSetting(KEY_MAX_ACTIVE_RULES, String.valueOf(Math.max(1, maxActiveRules)), "Circuit-breaker max active auto rules", updatedBy);
		settingsRepository.setSetting(KEY_DEFAULT_TTL_MINUTES, String.valueOf(Math.max(1, defaultTtlMinutes)), "Default TTL minutes for auto rules", updatedBy);
		settingsRepository.setSetting(KEY_AUTO_EXTEND, String.valueOf(autoExtendPersistent), "Auto-extend persistent attackers", updatedBy);
		settingsRepository.setSetting(KEY_MAX_EXTENSION_HOURS, String.valueOf(Math.max(1, maxExtensionHours)), "Max extension hours for auto rules", updatedBy);
		log.info("Auto-mitigation settings updated by '{}': enabled={}, dryRun={}, carpetMinSubnets={}, minReqsPerSubnet={}, windowHours={}, maxAuthReqs={}, protectedAsns='{}'",
				updatedBy, enabled, dryRun, carpetMinSubnets, safeMinReqsPerSubnet, carpetWindowHours, safeMaxAuthRequests, protectedAsns);
		invalidateRadarCache();
	}

	public void resetToDefaults(String updatedBy) {
		if (!properties.getMode().isBackgroundProcessingEnabled()) {
			throw new IllegalStateException("Auto-mitigation settings cannot be reset in " + properties.getMode() + " mode.");
		}
		settingsRepository.deleteSetting(KEY_ENABLED);
		settingsRepository.deleteSetting(KEY_DRY_RUN);
		settingsRepository.deleteSetting(KEY_CARPET_MIN_SUBNETS);
		settingsRepository.deleteSetting(KEY_CARPET_MIN_REQUESTS);
		settingsRepository.deleteSetting(KEY_CARPET_WINDOW_HOURS);
		settingsRepository.deleteSetting(KEY_PROTECTED_ASNS);
		settingsRepository.deleteSetting(KEY_MAX_RETURNING_PCT);
		settingsRepository.deleteSetting(KEY_MAX_AUTHENTICATED_REQUESTS);
		settingsRepository.deleteSetting(KEY_CARPET_MIN_REQUESTS_PER_SUBNET);
		settingsRepository.deleteSetting(KEY_MAX_ACTIVE_RULES);
		settingsRepository.deleteSetting(KEY_DEFAULT_TTL_MINUTES);
		settingsRepository.deleteSetting(KEY_AUTO_EXTEND);
		settingsRepository.deleteSetting(KEY_MAX_EXTENSION_HOURS);
		log.info("Auto-mitigation settings reset to application.yaml defaults by '{}'", updatedBy);
		invalidateRadarCache();
	}

	public record CarpetAttackCandidate(
			long asn,
			String asOrg,
			int activeSubnets,
			long totalRequests,
			long returningRequests,
			double returningRatioPct,
			List<String> eligibleSubnets,
			Map<String, Long> eligibleSubnetRequests
	) {
		public CarpetAttackCandidate(
				long asn,
				String asOrg,
				int activeSubnets,
				long totalRequests,
				long returningRequests,
				double returningRatioPct,
				List<String> eligibleSubnets
		) {
			this(asn, asOrg, activeSubnets, totalRequests, returningRequests, returningRatioPct, eligibleSubnets,
					toZeroVolumeMap(eligibleSubnets));
		}

		private static Map<String, Long> toZeroVolumeMap(List<String> subnets) {
			Map<String, Long> map = new LinkedHashMap<>();
			if (subnets != null) {
				for (String s : subnets) {
					map.put(s, 0L);
				}
			}
			return map;
		}
	}

	/** A single subnet competing for auto-rule capacity, scored by its own request volume. */
	private record SubnetCandidate(long asn, String subnet, long requests, int candidateRank) {}

	/**
	 * Scheduled scan running every 2 minutes across recent telemetry.
	 */
	@Scheduled(fixedDelay = 120_000, initialDelay = 30_000)
	public void scheduledAutonomousEvaluation() {
		if (!properties.getMode().isBackgroundProcessingEnabled()) {
			return;
		}
		EffectiveAutoSettings config = getEffectiveSettings();
		if (!config.enabled()) {
			return;
		}

		if (!scanRunning.compareAndSet(false, true)) {
			log.debug("Auto-mitigation evaluation already in progress, skipping tick");
			return;
		}

		try {
			runEvaluationCycle(config);
		} catch (Exception e) {
			log.error("Error during auto-mitigation evaluation: {}", e.getMessage(), e);
		} finally {
			scanRunning.set(false);
		}
	}

	/**
	 * Runs one full autonomous cycle (candidate enforcement plus persistent-attacker extensions)
	 * and pushes the resulting rule set to the fleet with a single coalesced sync.
	 */
	public List<CarpetAttackCandidate> runEvaluationCycle(EffectiveAutoSettings config) {
		return mitigationService.callWithDeferredFleetSync(() -> {
			List<CarpetAttackCandidate> candidates = evaluateAndEnforce(config);
			if (config.autoExtendPersistent()) {
				evaluateExtensions(config);
			}
			return candidates;
		});
	}

	/**
	 * Evaluates active carpet attack candidates and enforces auto-blocks or dry-run audit entries.
	 * <p>
	 * Capacity is allocated by priority: all eligible subnets of all candidate ASNs compete globally and the
	 * subnets with the highest own request volume are blocked first. When the circuit-breaker cap is reached,
	 * autonomous rules that have not blocked a single request since activation (observation phase elapsed)
	 * are released to make room for stronger candidates.
	 */
	public List<CarpetAttackCandidate> evaluateAndEnforce(EffectiveAutoSettings config) {
		if (!properties.getMode().isBackgroundProcessingEnabled()) {
			throw new IllegalStateException("Autonomous mitigation evaluation is disabled in " + properties.getMode() + " mode.");
		}
		return mitigationService.callWithDeferredFleetSync(() -> doEvaluateAndEnforce(config));
	}

	private List<CarpetAttackCandidate> doEvaluateAndEnforce(EffectiveAutoSettings config) {
		Instant now = Instant.now();
		List<MitigationRule> activeRules = mitigationService.getActiveRules();
		Set<String> activeCidrs = new HashSet<>();
		for (MitigationRule r : activeRules) {
			activeCidrs.add(r.cidr().toLowerCase(Locale.ROOT));
		}
		long totalActiveCount = activeRules.size();
		long currentAutoCount = activeRules.stream()
				.filter(r -> MitigationRule.SOURCE_AUTO_CARPET.equalsIgnoreCase(r.source())
						|| MitigationRule.SOURCE_AUTO_RULE.equalsIgnoreCase(r.source()))
				.count();
		long nonAutoCount = totalActiveCount - currentAutoCount;
		long maxAllowedAutoRules = Math.max(0L, config.maxActiveRules() - nonAutoCount);

		List<CarpetAttackCandidate> candidates = findCarpetAttackCandidates(config, config.carpetWindowHours());

		if (candidates.isEmpty()) {
			releaseExcessUnusedAutoRulesIfNeeded(config, currentAutoCount, maxAllowedAutoRules);
			return List.of();
		}

		Set<Long> protectedAsns = config.getProtectedAsnSet();
		Map<Long, CarpetAttackCandidate> candidatesByAsn = new LinkedHashMap<>();
		List<SubnetCandidate> pending = new ArrayList<>();

		int rank = 0;
		for (CarpetAttackCandidate c : candidates) {
			if (protectedAsns.contains(c.asn())) {
				log.info("[AUTO-SKIP] ASN {} ({}) is on the protected ASNs list. Skipping autonomous block.", c.asn(), c.asOrg());
				mitigationService.recordAudit(null, "ASN-" + c.asn(), "AUTO_SKIPPED_PROTECTED_ASN",
						"Skipped autonomous block for ASN " + c.asn() + " (" + (c.asOrg() != null ? c.asOrg() : "Unknown")
								+ ") because it is on the protected ASNs list (" + config.protectedAsns() + ").",
						0, "AUTO_ENGINE");
				continue;
			}
			candidatesByAsn.put(c.asn(), c);
			for (Map.Entry<String, Long> e : c.eligibleSubnetRequests().entrySet()) {
				// Subnets that already have an active rule keep their timers and are never re-created
				if (!activeCidrs.contains(e.getKey().toLowerCase(Locale.ROOT))) {
					pending.add(new SubnetCandidate(c.asn(), e.getKey(), e.getValue() != null ? e.getValue() : 0L, rank));
				}
			}
			rank++;
		}

		if (pending.isEmpty()) {
			releaseExcessUnusedAutoRulesIfNeeded(config, currentAutoCount, maxAllowedAutoRules);
			return candidates;
		}

		// Priority: highest per-subnet volume first, ties keep the ASN order (largest ASN volume first)
		pending.sort(Comparator.comparingLong(SubnetCandidate::requests).reversed()
				.thenComparingInt(SubnetCandidate::candidateRank));

		long freeCapacity = Math.max(0L, maxAllowedAutoRules - currentAutoCount);
		int released = 0;
		if ((pending.size() > freeCapacity || currentAutoCount > maxAllowedAutoRules) && currentAutoCount > 0) {
			long deficit = (currentAutoCount - maxAllowedAutoRules)
					+ (maxAllowedAutoRules > 0 ? pending.size() : 0L);
			int needed = (int) Math.min(currentAutoCount, Math.max(0L, deficit));
			released = releaseUnusedAutoRulesForCapacity(
					config,
					needed,
					"Released to free capacity for higher-priority carpet attack subnets (no blocked hits since activation)",
					"[DRY-RUN] Would release {} unused autonomous rule(s) to free capacity for higher-priority subnets");
		}

		long remainingAutoAfterRelease = Math.max(0L, currentAutoCount - released);
		long availableCapacity = Math.max(0L, maxAllowedAutoRules - remainingAutoAfterRelease);
		int allowed = (int) Math.min(pending.size(), availableCapacity);
		List<SubnetCandidate> selected = pending.subList(0, allowed);
		List<SubnetCandidate> skipped = pending.subList(allowed, pending.size());

		// Group selected subnets per ASN (preserving priority order inside each batch)
		Map<Long, List<String>> selectedByAsn = new LinkedHashMap<>();
		for (Long asn : candidatesByAsn.keySet()) {
			selectedByAsn.put(asn, new ArrayList<>());
		}
		for (SubnetCandidate s : selected) {
			selectedByAsn.get(s.asn()).add(s.subnet());
		}

		for (Map.Entry<Long, List<String>> entry : selectedByAsn.entrySet()) {
			List<String> targetSubnets = entry.getValue();
			if (targetSubnets.isEmpty()) {
				continue;
			}
			CarpetAttackCandidate c = candidatesByAsn.get(entry.getKey());
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
				mitigationService.createBatchBlocks(
						targetSubnets,
						config.defaultTtlMinutes(),
						reason,
						MitigationRule.SOURCE_AUTO_CARPET,
						batchId,
						"AUTO_ENGINE"
				);
				if (notificationService != null) {
					notificationService.sendAutoBlockAlert(c.asn(), c.asOrg(), targetSubnets, batchId, config.defaultTtlMinutes(), reason);
				}
			}
		}

		if (!skipped.isEmpty()) {
			Set<Long> skippedAsns = new LinkedHashSet<>();
			for (SubnetCandidate s : skipped) {
				skippedAsns.add(s.asn());
			}
			long firstSkippedAsn = skippedAsns.iterator().next();
			long strongestSkipped = skipped.getFirst().requests();
			long effectiveAutoCount = remainingAutoAfterRelease + selected.size();
			long effectiveActiveCount = nonAutoCount + effectiveAutoCount;
			log.warn("Auto-mitigation circuit breaker reached ({}/{} active rules: {} auto, {} manual/other). Skipped {} lower-priority subnet(s) across ASN(s) {} (max {} reqs/subnet); released {} unused rule(s).",
					effectiveActiveCount, config.maxActiveRules(), effectiveAutoCount, nonAutoCount,
					skipped.size(), skippedAsns, strongestSkipped, released);
			mitigationService.recordAudit(null, "ASN-" + firstSkippedAsn, "AUTO_CIRCUIT_BREAKER",
					"Circuit breaker limit of " + config.maxActiveRules() + " active rules reached ("
							+ effectiveActiveCount + " active: " + effectiveAutoCount + " auto, " + nonAutoCount
							+ " manual/other). Skipped " + skipped.size() + " lower-priority subnet(s) across ASN(s) "
							+ skippedAsns + " (strongest skipped subnet: " + strongestSkipped + " reqs); released "
							+ released + " unused rule(s) to make room.",
					0, "AUTO_ENGINE");
			if (notificationService != null) {
				notificationService.sendCircuitBreakerAlert(effectiveActiveCount, config.maxActiveRules(), firstSkippedAsn, skipped.size());
			}
		}

		if (!selected.isEmpty() && !config.dryRun()) {
			invalidateRadarCache();
		}

		return candidates;
	}

	private int releaseExcessUnusedAutoRulesIfNeeded(EffectiveAutoSettings config, long currentAutoCount, long maxAllowedAutoRules) {
		long excessAuto = currentAutoCount - maxAllowedAutoRules;
		if (excessAuto <= 0 || currentAutoCount <= 0) {
			return 0;
		}
		int needed = (int) Math.min(currentAutoCount, excessAuto);
		return releaseUnusedAutoRulesForCapacity(
				config,
				needed,
				"Released excess unused autonomous rule above circuit breaker cap (no blocked hits since activation)",
				"[DRY-RUN] Would release {} excess unused autonomous rule(s) above circuit breaker cap");
	}

	private int releaseUnusedAutoRulesForCapacity(EffectiveAutoSettings config, int needed, String releaseReason, String dryRunLogMessage) {
		if (needed <= 0) {
			return 0;
		}
		mitigationService.refreshDeterrenceMetrics();
		if (config.dryRun()) {
			int released = mitigationService.countUnusedAutoRules(needed);
			if (released > 0) {
				log.info(dryRunLogMessage, released);
			}
			return released;
		}
		return mitigationService.releaseUnusedAutoRules(needed, releaseReason, "AUTO_ENGINE");
	}

	/**
	 * Detects ASNs distributing traffic across multiple unauthenticated subnets with very low returning visitor ratios.
	 */
	public List<CarpetAttackCandidate> findCarpetAttackCandidates(EffectiveAutoSettings config, int hours) {
		int safeHours = Math.max(1, Math.min(hours, 720));
		Instant cutoff = Instant.now().minus(Duration.ofHours(safeHours));

		String sql = """
				SELECT
				    (asn + 0) AS asn,
				    MAX(as_org) AS as_org,
				    COUNT(DISTINCT subnet_group) AS active_subnets,
				    SUM(total_requests) AS total_requests,
				    SUM(returning_requests) AS total_returning,
				    SUM(authenticated_requests) AS total_authenticated
				FROM client_subnet_rollups
				WHERE bucket_start >= ?
				  AND asn IS NOT NULL
				  AND (asn + 0) > 0
				  AND (client_type IS NULL OR client_type NOT IN ('SEARCH_ENGINE', 'AI_CRAWLER', 'PRIVATE_NETWORK', 'INTERNAL_NETWORK'))
				GROUP BY (asn + 0)
				HAVING COUNT(DISTINCT subnet_group) >= ?
				   AND SUM(total_requests) >= ?
				   AND SUM(authenticated_requests) <= ?
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
				// Individual subnets must strictly have 0 authenticated requests, a returning ratio
				// <= maxReturningRatioPct and at least carpetMinRequestsPerSubnet own requests
				Map<String, Long> eligible = findEligibleSubnetsForAsn(asn, safeHours,
						config.maxReturningRatioPct(), config.carpetMinRequestsPerSubnet());
				if (eligible.size() >= config.carpetMinSubnets()) {
					candidates.add(new CarpetAttackCandidate(
							asn, asOrg, activeSubnets, totalReq, returningReq, returningPct,
							new ArrayList<>(eligible.keySet()), eligible
					));
				}
			}
		}, java.sql.Timestamp.from(cutoff), config.carpetMinSubnets(), config.carpetMinRequests(), Math.max(0L, config.maxAuthenticatedRequests()));

		return candidates;
	}

	/**
	 * Resolves eligible subnets for the given ASN using a single set-based query and in-memory CIDR validation
	 * (avoiding per-subnet SQL preflight N+1 queries).
	 *
	 * @return Eligible subnets of the ASN mapped to their request volume in the window, highest volume first
	 */
	private Map<String, Long> findEligibleSubnetsForAsn(long asn, int hours, double maxReturningPct, long minRequestsPerSubnet) {
		Instant now = Instant.now();
		Instant windowCutoff = now.minus(Duration.ofHours(hours));
		Instant safetyCutoff24h = now.minus(Duration.ofHours(Math.max(hours, 24)));
		int minV4 = mitigationService.getEffectiveMinIpv4Prefix();
		int minV6 = mitigationService.getEffectiveMinIpv6Prefix();

		String sql = """
				SELECT
				    subnet_group,
				    SUM(CASE WHEN bucket_start >= ? THEN total_requests ELSE 0 END) AS sub_total,
				    SUM(CASE WHEN bucket_start >= ? THEN returning_requests ELSE 0 END) AS sub_returning,
				    SUM(authenticated_requests) AS sub_auth_24h,
				    MAX(CASE WHEN client_type IN ('SEARCH_ENGINE', 'AI_CRAWLER', 'PRIVATE_NETWORK', 'INTERNAL_NETWORK') THEN 1 ELSE 0 END) AS is_excluded
				FROM client_subnet_rollups
				WHERE asn = ?
				  AND bucket_start >= ?
				GROUP BY subnet_group
				HAVING SUM(authenticated_requests) = 0
				   AND MAX(CASE WHEN client_type IN ('SEARCH_ENGINE', 'AI_CRAWLER', 'PRIVATE_NETWORK', 'INTERNAL_NETWORK') THEN 1 ELSE 0 END) = 0
				   AND SUM(CASE WHEN bucket_start >= ? THEN total_requests ELSE 0 END) >= ?
				ORDER BY sub_total DESC
				""";

		Map<String, Long> result = new LinkedHashMap<>();
		java.sql.Timestamp winTs = java.sql.Timestamp.from(windowCutoff);
		java.sql.Timestamp safetyTs = java.sql.Timestamp.from(safetyCutoff24h);
		jdbcTemplate.query(sql, rs -> {
			String sub = rs.getString("subnet_group");
			long total = rs.getLong("sub_total");
			long returning = rs.getLong("sub_returning");
			double subReturnPct = total > 0 ? (returning * 100.0 / total) : 0.0;

			if (subReturnPct <= maxReturningPct && sub != null && !sub.isBlank()) {
				try {
					MitigationService.NormalizedCidr norm = MitigationService.normalizeAndValidateCidr(sub, minV4, minV6);
					if (org.henbru.antidos.collector.util.IpNetworkUtil.getPrivateNetworkDescription(norm.canonicalCidr()) == null) {
						result.put(norm.canonicalCidr(), total);
					}
				} catch (IllegalArgumentException ignored) {
				}
			}
		}, winTs, winTs, asn, safetyTs, winTs, Math.max(1L, minRequestsPerSubnet));

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
		if (!properties.getMode().isBackgroundProcessingEnabled()) {
			throw new IllegalStateException("Autonomous rule extension is disabled in " + properties.getMode() + " mode.");
		}
		return mitigationService.callWithDeferredFleetSync(() -> doEvaluateExtensions(config));
	}

	private int doEvaluateExtensions(EffectiveAutoSettings config) {
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

	public void invalidateRadarCache() {
		this.cachedRadar = null;
		this.cachedRadarHours = -1;
		this.cachedRadarAtMillis = 0L;
	}

	/**
	 * Returns the recently cached Carpet Attack Radar snapshot if still fresh ({@code < 60s}), or {@code null}.
	 */
	public List<CarpetRadarEntry> getCachedCarpetRadar(int hours) {
		int safeHours = Math.max(1, Math.min(hours, 720));
		List<CarpetRadarEntry> snapshot = this.cachedRadar;
		if (snapshot != null && this.cachedRadarHours == safeHours
				&& (System.currentTimeMillis() - this.cachedRadarAtMillis) < RADAR_CACHE_TTL_MS) {
			return snapshot;
		}
		return null;
	}

	/**
	 * Scans recent telemetry across all active ASNs and evaluates each against the deterministic
	 * auto-mitigation safety guardrails. Provides full transparency into why an ASN was qualified or suppressed.
	 */
	public List<CarpetRadarEntry> getCarpetRadar(int hours) {
		EffectiveAutoSettings config = getEffectiveSettings();
		int safeHours = Math.max(1, Math.min(hours, 720));
		Instant cutoff = Instant.now().minus(Duration.ofHours(safeHours));

		String sql = """
				SELECT
				    (asn + 0) AS asn,
				    MAX(as_org) AS as_org,
				    MAX(country_code) AS country_code,
				    COUNT(DISTINCT subnet_group) AS active_subnets,
				    SUM(total_requests) AS total_requests,
				    SUM(returning_requests) AS total_returning,
				    SUM(authenticated_requests) AS total_authenticated
				FROM client_subnet_rollups
				WHERE bucket_start >= ?
				  AND asn IS NOT NULL
				  AND (asn + 0) > 0
				  AND (client_type IS NULL OR client_type NOT IN ('SEARCH_ENGINE', 'AI_CRAWLER', 'PRIVATE_NETWORK', 'INTERNAL_NETWORK'))
				GROUP BY (asn + 0)
				HAVING COUNT(DISTINCT subnet_group) >= 2 OR SUM(total_requests) >= 500
				ORDER BY total_requests DESC
				LIMIT 40
				""";

		List<MitigationRule> activeRules = mitigationService.getActiveRules();
		Set<Long> activelyMitigatedAsns = new HashSet<>();
		for (MitigationRule r : activeRules) {
			if (r.asn() != null) {
				activelyMitigatedAsns.add(r.asn());
			}
		}
		Set<Long> protectedAsns = config.getProtectedAsnSet();
		List<CarpetRadarEntry> entries = new ArrayList<>();

		jdbcTemplate.query(sql, rs -> {
			long asn = rs.getLong("asn");
			String rawAsOrg = rs.getString("as_org");
			String asOrg = resolveAsnOrg(asn, rawAsOrg);
			String countryCode = rs.getString("country_code");
			int activeSubnets = rs.getInt("active_subnets");
			long totalReq = rs.getLong("total_requests");
			long returningReq = rs.getLong("total_returning");
			long authReq = rs.getLong("total_authenticated");
			double returningPct = totalReq > 0 ? (returningReq * 100.0 / totalReq) : 0.0;
			returningPct = Math.round(returningPct * 10.0) / 10.0;

			boolean isProtected = protectedAsns.contains(asn);
			boolean hasActiveRule = activelyMitigatedAsns.contains(asn);

			List<String> topSubnets = findTopSubnetsForAsn(asn, safeHours, 5);

			String status;
			String statusReason;
			String badgeClass;
			String icon;

			if (isProtected) {
				status = "PROTECTED_ASN";
				statusReason = "Protected ASN (exempt from automated mitigation: " + config.protectedAsns() + ")";
				badgeClass = "badge-info";
				icon = "🛡️";
			} else if (hasActiveRule) {
				status = "ACTIVE_MITIGATION";
				statusReason = "ASN subnets are currently active dynamic mitigation rules";
				badgeClass = "badge-success";
				icon = "🔒";
			} else if (authReq > config.maxAuthenticatedRequests()) {
				status = "SUPPRESSED_AUTH";
				statusReason = config.maxAuthenticatedRequests() > 0
						? "Suppressed: " + String.format("%,d", authReq) + " authenticated requests exceed max allowed (" + String.format("%,d", config.maxAuthenticatedRequests()) + ")"
						: "Suppressed: " + String.format("%,d", authReq) + " authenticated requests detected (human university sessions)";
				badgeClass = "badge-warning";
				icon = "👥";
			} else if (activeSubnets >= config.carpetMinSubnets() && totalReq >= config.carpetMinRequests()) {
				if (returningPct <= config.maxReturningRatioPct()) {
					int eligibleCount = findEligibleSubnetsForAsn(asn, safeHours, config.maxReturningRatioPct(),
							config.carpetMinRequestsPerSubnet()).size();
					if (eligibleCount < config.carpetMinSubnets()) {
						status = "BELOW_SUBNET_THRESHOLD";
						statusReason = "Below threshold: " + eligibleCount + " / " + config.carpetMinSubnets()
								+ " eligible subnets (unauthenticated"
								+ (config.carpetMinRequestsPerSubnet() > 0 ? ", >= " + config.carpetMinRequestsPerSubnet() + " reqs each" : "")
								+ ")";
						badgeClass = "badge-secondary";
						icon = "ℹ️";
					} else {
						status = "QUALIFIED";
						statusReason = config.dryRun()
								? "QUALIFIED (Dry-Run): Meets all criteria! Would autonomously block " + eligibleCount + " unauthenticated subnets."
								: "QUALIFIED (Live): Meets all criteria! Eligible for autonomous blocking (" + eligibleCount + " unauthenticated subnets).";
						badgeClass = "badge-danger";
						icon = "🚨";
					}
				} else {
					status = "SUPPRESSED_RETURNING_RATIO";
					statusReason = "Suppressed: Returning visitor ratio (" + String.format("%.1f%%", returningPct)
							+ ") exceeds safety limit (" + String.format("%.1f%%", config.maxReturningRatioPct()) + ")";
					badgeClass = "badge-warning";
					icon = "🟡";
				}
			} else if (activeSubnets < config.carpetMinSubnets()) {
				status = "BELOW_SUBNET_THRESHOLD";
				statusReason = "Below threshold: " + activeSubnets + " / " + config.carpetMinSubnets() + " required subnets";
				badgeClass = "badge-secondary";
				icon = "ℹ️";
			} else {
				status = "BELOW_REQUEST_THRESHOLD";
				statusReason = "Below threshold: " + String.format("%,d", totalReq) + " / " + String.format("%,d", config.carpetMinRequests()) + " required requests";
				badgeClass = "badge-secondary";
				icon = "ℹ️";
			}

			entries.add(new CarpetRadarEntry(
					asn,
					asOrg,
					countryCode,
					activeSubnets,
					totalReq,
					returningReq,
					returningPct,
					authReq,
					isProtected,
					hasActiveRule,
					status,
					statusReason,
					badgeClass,
					icon,
					topSubnets
			));
		}, java.sql.Timestamp.from(cutoff));

		List<CarpetRadarEntry> immutableSnapshot = List.copyOf(entries);
		this.cachedRadar = immutableSnapshot;
		this.cachedRadarHours = safeHours;
		this.cachedRadarAtMillis = System.currentTimeMillis();
		return immutableSnapshot;
	}

	private List<String> findTopSubnetsForAsn(long asn, int hours, int limit) {
		Instant cutoff = Instant.now().minus(Duration.ofHours(hours));
		String sql = """
				SELECT subnet_group
				FROM client_subnet_rollups
				WHERE bucket_start >= ? AND asn = ? AND subnet_group IS NOT NULL AND subnet_group != ''
				GROUP BY subnet_group
				ORDER BY SUM(total_requests) DESC
				LIMIT ?
				""";
		try {
			return jdbcTemplate.query(sql, (rs, rowNum) -> rs.getString("subnet_group"),
					java.sql.Timestamp.from(cutoff), asn, Math.max(1, limit));
		} catch (Exception e) {
			return List.of();
		}
	}
}
