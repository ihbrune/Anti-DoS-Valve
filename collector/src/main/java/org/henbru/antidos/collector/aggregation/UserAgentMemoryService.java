package org.henbru.antidos.collector.aggregation;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.enrichment.BrowserVersionSyncService;
import org.henbru.antidos.collector.model.BrowserVersionLagAssessment;
import org.henbru.antidos.collector.model.EffectiveUaHeuristicSettings;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.UserAgentAutoVerdict;
import org.henbru.antidos.collector.model.UserAgentDrilldownDto;
import org.henbru.antidos.collector.model.UserAgentFamily;
import org.henbru.antidos.collector.model.UserAgentHourlyPoint;
import org.henbru.antidos.collector.model.UserAgentManualOverride;
import org.henbru.antidos.collector.model.UserAgentOriginSummary;
import org.henbru.antidos.collector.model.UserAgentProfile;
import org.henbru.antidos.collector.security.CollectorAuthContext;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.SystemSettingsRepository;
import org.henbru.antidos.collector.storage.UserAgentMemoryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Service managing long-term User-Agent memory ({@code dim_user_agent}), hourly evaluation
 * rollups ({@code user_agent_hourly_rollups}), configurable 3-pillar heuristic thresholds with
 * Stage-0 immunity barriers (internal networks, verified search engines, authenticated sessions),
 * and non-overwritable manual overrides.
 */
@Service
public class UserAgentMemoryService {

	private static final Logger log = LoggerFactory.getLogger(UserAgentMemoryService.class);

	public static final String KEY_INTERNAL_MIN_RATIO_PCT = "ua.heuristic.internal_immunity_min_ratio_pct";
	public static final String KEY_INTERNAL_MIN_REQUESTS = "ua.heuristic.internal_immunity_min_requests";
	public static final String KEY_SEARCH_ENGINE_MIN_RATIO_PCT = "ua.heuristic.search_engine_immunity_min_ratio_pct";
	public static final String KEY_AUTH_MIN_SAMPLE_RATIO_PCT = "ua.heuristic.auth_immunity_min_sample_ratio_pct";
	public static final String KEY_AUTH_MIN_SLOT_RATIO_PCT = "ua.heuristic.auth_immunity_min_slot_ratio_pct";

	public static final String KEY_SPREAD_MIN_REQUESTS = "ua.heuristic.spread_min_requests";
	public static final String KEY_SPREAD_MIN_SUBNETS = "ua.heuristic.spread_min_subnets";
	public static final String KEY_SPREAD_MIN_ASNS = "ua.heuristic.spread_min_asns";
	public static final String KEY_SPREAD_MAX_AVG_SLOT_REQS = "ua.heuristic.spread_max_avg_slot_requests";
	public static final String KEY_SPREAD_MIN_VERSION_LAG = "ua.heuristic.spread_min_version_lag_majors";

	public static final String KEY_CORRELATED_MIN_REQUESTS = "ua.heuristic.correlated_min_requests";
	public static final String KEY_CORRELATED_MIN_INCIDENT_PCT = "ua.heuristic.correlated_min_incident_ratio_pct";
	public static final String KEY_CORRELATED_MIN_MITIGATED_ASN_PCT = "ua.heuristic.correlated_min_mitigated_asn_ratio_pct";
	public static final String KEY_CORRELATED_MIN_UA_MISMATCH_PCT = "ua.heuristic.correlated_min_ua_mismatch_ratio_pct";

	public static final String KEY_DATACENTER_MIN_REQUESTS = "ua.heuristic.datacenter_min_requests";
	public static final String KEY_DATACENTER_MIN_RATIO_PCT = "ua.heuristic.datacenter_min_ratio_pct";

	private static final List<String> ALL_SETTING_KEYS = List.of(
			KEY_INTERNAL_MIN_RATIO_PCT, KEY_INTERNAL_MIN_REQUESTS, KEY_SEARCH_ENGINE_MIN_RATIO_PCT,
			KEY_AUTH_MIN_SAMPLE_RATIO_PCT, KEY_AUTH_MIN_SLOT_RATIO_PCT,
			KEY_SPREAD_MIN_REQUESTS, KEY_SPREAD_MIN_SUBNETS, KEY_SPREAD_MIN_ASNS,
			KEY_SPREAD_MAX_AVG_SLOT_REQS, KEY_SPREAD_MIN_VERSION_LAG,
			KEY_CORRELATED_MIN_REQUESTS, KEY_CORRELATED_MIN_INCIDENT_PCT,
			KEY_CORRELATED_MIN_MITIGATED_ASN_PCT, KEY_CORRELATED_MIN_UA_MISMATCH_PCT,
			KEY_DATACENTER_MIN_REQUESTS, KEY_DATACENTER_MIN_RATIO_PCT
	);

	private final UserAgentMemoryRepository memoryRepository;
	private final CollectorProperties properties;
	private final SystemSettingsRepository settingsRepository;
	private final MitigationRuleRepository mitigationRuleRepository;
	private final ClientEventRepository clientEventRepository;
	private final BrowserVersionSyncService browserVersionSyncService;
	private final JdbcTemplate jdbcTemplate;
	private final boolean isPostgres;
	private final AtomicBoolean initialBackfillChecked = new AtomicBoolean(false);

	@Autowired
	public UserAgentMemoryService(
			UserAgentMemoryRepository memoryRepository,
			CollectorProperties properties,
			@Autowired(required = false) SystemSettingsRepository settingsRepository,
			@Autowired(required = false) MitigationRuleRepository mitigationRuleRepository,
			@Autowired(required = false) ClientEventRepository clientEventRepository,
			@Autowired(required = false) BrowserVersionSyncService browserVersionSyncService,
			@Autowired(required = false) JdbcTemplate jdbcTemplate
	) {
		this.memoryRepository = memoryRepository;
		this.properties = properties != null ? properties : new CollectorProperties();
		this.settingsRepository = settingsRepository;
		this.mitigationRuleRepository = mitigationRuleRepository;
		this.clientEventRepository = clientEventRepository;
		this.browserVersionSyncService = browserVersionSyncService;
		this.jdbcTemplate = jdbcTemplate;
		this.isPostgres = checkIsPostgres(jdbcTemplate);
	}

	public UserAgentMemoryService(
			UserAgentMemoryRepository memoryRepository,
			CollectorProperties properties,
			SystemSettingsRepository settingsRepository,
			MitigationRuleRepository mitigationRuleRepository,
			BrowserVersionSyncService browserVersionSyncService
	) {
		this(memoryRepository, properties, settingsRepository, mitigationRuleRepository, null, browserVersionSyncService, null);
	}

	private static boolean checkIsPostgres(JdbcTemplate jdbcTemplate) {
		try {
			if (jdbcTemplate != null && jdbcTemplate.getDataSource() != null) {
				try (java.sql.Connection conn = jdbcTemplate.getDataSource().getConnection()) {
					String product = conn.getMetaData().getDatabaseProductName();
					return product != null && product.toLowerCase(Locale.ROOT).contains("postgres");
				}
			}
		} catch (Exception ignored) {
		}
		return false;
	}

	public record EvaluationOutcome(
			UserAgentAutoVerdict verdict,
			String reason,
			BrowserVersionLagAssessment versionAssessment,
			Integer parsedMajorVersion,
			Integer versionLagMajors,
			double internalRatioPct,
			double searchEngineRatioPct,
			double sampleAuthRatioPct,
			double slotAuthRatioPct,
			double incidentEventRatioPct,
			double mitigatedAsnRatioPct,
			double uaMismatchRatioPct,
			double datacenterRatioPct,
			double residentialRatioPct,
			double avgRequestsPerSlot,
			boolean residentialZeroAuthAnomaly
	) {
		public boolean hasPositiveMitigationMatch(double thresholdMitigatedPct) {
			return mitigatedAsnRatioPct > 0.0 && mitigatedAsnRatioPct >= Math.min(thresholdMitigatedPct, 25.0);
		}
	}

	public record EvaluationInput(
			String userAgent,
			UserAgentFamily family,
			long totalRequests,
			int eventCount,
			int blockedEvents,
			int markedEvents,
			int distinctSubnets,
			int distinctAsns,
			int authSamples,
			long authRequests,
			long internalRequests,
			long searchEngineRequests,
			long datacenterRequests,
			long residentialRequests,
			long mitigatedAsnRequests,
			long uaMismatchRequests,
			boolean mitigationOriginMatch,
			String mitigationMatchDetails
	) {}

	public EffectiveUaHeuristicSettings getEffectiveSettings() {
		CollectorProperties.UserAgentHeuristicConfig yaml = properties.getUserAgentHeuristics();
		if (settingsRepository == null) {
			return new EffectiveUaHeuristicSettings(
					yaml.getInternalImmunityMinRatioPct(),
					yaml.getInternalImmunityMinRequests(),
					yaml.getSearchEngineImmunityMinRatioPct(),
					yaml.getAuthImmunityMinSampleRatioPct(),
					yaml.getAuthImmunityMinSlotRatioPct(),
					yaml.getSpreadMinRequests(),
					yaml.getSpreadMinSubnets(),
					yaml.getSpreadMinAsns(),
					yaml.getSpreadMaxAvgSlotRequests(),
					yaml.getSpreadMinVersionLagMajors(),
					yaml.getCorrelatedMinRequests(),
					yaml.getCorrelatedMinIncidentRatioPct(),
					yaml.getCorrelatedMinMitigatedAsnRatioPct(),
					yaml.getCorrelatedMinUaMismatchRatioPct(),
					yaml.getDatacenterMinRequests(),
					yaml.getDatacenterMinRatioPct(),
					false
			);
		}

		Optional<Double> internalMinPct = settingsRepository.getDouble(KEY_INTERNAL_MIN_RATIO_PCT);
		Optional<Long> internalMinReqs = settingsRepository.getLong(KEY_INTERNAL_MIN_REQUESTS);
		Optional<Double> seMinPct = settingsRepository.getDouble(KEY_SEARCH_ENGINE_MIN_RATIO_PCT);
		Optional<Double> authSamplePct = settingsRepository.getDouble(KEY_AUTH_MIN_SAMPLE_RATIO_PCT);
		Optional<Double> authSlotPct = settingsRepository.getDouble(KEY_AUTH_MIN_SLOT_RATIO_PCT);
		Optional<Long> spreadReqs = settingsRepository.getLong(KEY_SPREAD_MIN_REQUESTS);
		Optional<Integer> spreadSubnets = settingsRepository.getInt(KEY_SPREAD_MIN_SUBNETS);
		Optional<Integer> spreadAsns = settingsRepository.getInt(KEY_SPREAD_MIN_ASNS);
		Optional<Double> spreadAvgSlot = settingsRepository.getDouble(KEY_SPREAD_MAX_AVG_SLOT_REQS);
		Optional<Integer> spreadLag = settingsRepository.getInt(KEY_SPREAD_MIN_VERSION_LAG);
		Optional<Long> corrReqs = settingsRepository.getLong(KEY_CORRELATED_MIN_REQUESTS);
		Optional<Double> corrIncPct = settingsRepository.getDouble(KEY_CORRELATED_MIN_INCIDENT_PCT);
		Optional<Double> corrMitPct = settingsRepository.getDouble(KEY_CORRELATED_MIN_MITIGATED_ASN_PCT);
		Optional<Double> corrMmPct = settingsRepository.getDouble(KEY_CORRELATED_MIN_UA_MISMATCH_PCT);
		Optional<Long> dcReqs = settingsRepository.getLong(KEY_DATACENTER_MIN_REQUESTS);
		Optional<Double> dcPct = settingsRepository.getDouble(KEY_DATACENTER_MIN_RATIO_PCT);

		boolean hasOverrides = internalMinPct.isPresent() || internalMinReqs.isPresent() || seMinPct.isPresent()
				|| authSamplePct.isPresent() || authSlotPct.isPresent()
				|| spreadReqs.isPresent() || spreadSubnets.isPresent() || spreadAsns.isPresent()
				|| spreadAvgSlot.isPresent() || spreadLag.isPresent()
				|| corrReqs.isPresent() || corrIncPct.isPresent() || corrMitPct.isPresent() || corrMmPct.isPresent()
				|| dcReqs.isPresent() || dcPct.isPresent();

		return new EffectiveUaHeuristicSettings(
				internalMinPct.orElse(yaml.getInternalImmunityMinRatioPct()),
				internalMinReqs.orElse(yaml.getInternalImmunityMinRequests()),
				seMinPct.orElse(yaml.getSearchEngineImmunityMinRatioPct()),
				authSamplePct.orElse(yaml.getAuthImmunityMinSampleRatioPct()),
				authSlotPct.orElse(yaml.getAuthImmunityMinSlotRatioPct()),
				spreadReqs.orElse(yaml.getSpreadMinRequests()),
				spreadSubnets.orElse(yaml.getSpreadMinSubnets()),
				spreadAsns.orElse(yaml.getSpreadMinAsns()),
				spreadAvgSlot.orElse(yaml.getSpreadMaxAvgSlotRequests()),
				spreadLag.orElse(yaml.getSpreadMinVersionLagMajors()),
				corrReqs.orElse(yaml.getCorrelatedMinRequests()),
				corrIncPct.orElse(yaml.getCorrelatedMinIncidentRatioPct()),
				corrMitPct.orElse(yaml.getCorrelatedMinMitigatedAsnRatioPct()),
				corrMmPct.orElse(yaml.getCorrelatedMinUaMismatchRatioPct()),
				dcReqs.orElse(yaml.getDatacenterMinRequests()),
				dcPct.orElse(yaml.getDatacenterMinRatioPct()),
				hasOverrides
		);
	}

	public EffectiveUaHeuristicSettings updateSettings(EffectiveUaHeuristicSettings next, String updatedBy) {
		if (!properties.canPerformSystemAdmin() || CollectorAuthContext.isAiAgent()) {
			throw new IllegalStateException("Updating User-Agent heuristic thresholds requires FULL admin mode.");
		}
		if (settingsRepository == null) {
			throw new IllegalStateException("SystemSettingsRepository is unavailable.");
		}
		String actor = updatedBy != null && !updatedBy.isBlank() ? updatedBy : "ADMIN";
		settingsRepository.setSetting(KEY_INTERNAL_MIN_RATIO_PCT, String.valueOf(clampPct(next.internalImmunityMinRatioPct())), "UA internal network immunity min %", actor);
		settingsRepository.setSetting(KEY_INTERNAL_MIN_REQUESTS, String.valueOf(Math.max(1L, next.internalImmunityMinRequests())), "UA internal network immunity min requests", actor);
		settingsRepository.setSetting(KEY_SEARCH_ENGINE_MIN_RATIO_PCT, String.valueOf(clampPct(next.searchEngineImmunityMinRatioPct())), "UA search engine immunity min %", actor);
		settingsRepository.setSetting(KEY_AUTH_MIN_SAMPLE_RATIO_PCT, String.valueOf(clampPct(next.authImmunityMinSampleRatioPct())), "UA auth sample immunity min %", actor);
		settingsRepository.setSetting(KEY_AUTH_MIN_SLOT_RATIO_PCT, String.valueOf(clampPct(next.authImmunityMinSlotRatioPct())), "UA auth slot immunity min %", actor);

		settingsRepository.setSetting(KEY_SPREAD_MIN_REQUESTS, String.valueOf(Math.max(1L, next.spreadMinRequests())), "UA Pillar 1 ultra-spread min requests", actor);
		settingsRepository.setSetting(KEY_SPREAD_MIN_SUBNETS, String.valueOf(Math.max(1, next.spreadMinSubnets())), "UA Pillar 1 ultra-spread min subnets", actor);
		settingsRepository.setSetting(KEY_SPREAD_MIN_ASNS, String.valueOf(Math.max(1, next.spreadMinAsns())), "UA Pillar 1 ultra-spread min ASNs", actor);
		settingsRepository.setSetting(KEY_SPREAD_MAX_AVG_SLOT_REQS, String.valueOf(Math.max(0.1, next.spreadMaxAvgSlotRequests())), "UA Pillar 1 ultra-spread max avg reqs/slot", actor);
		settingsRepository.setSetting(KEY_SPREAD_MIN_VERSION_LAG, String.valueOf(Math.max(1, next.spreadMinVersionLagMajors())), "UA Pillar 1 ultra-spread min browser version lag", actor);

		settingsRepository.setSetting(KEY_CORRELATED_MIN_REQUESTS, String.valueOf(Math.max(1L, next.correlatedMinRequests())), "UA Pillar 2 correlated min requests", actor);
		settingsRepository.setSetting(KEY_CORRELATED_MIN_INCIDENT_PCT, String.valueOf(clampPct(next.correlatedMinIncidentRatioPct())), "UA Pillar 2 min incident event %", actor);
		settingsRepository.setSetting(KEY_CORRELATED_MIN_MITIGATED_ASN_PCT, String.valueOf(clampPct(next.correlatedMinMitigatedAsnRatioPct())), "UA Pillar 2 min mitigated ASN request %", actor);
		settingsRepository.setSetting(KEY_CORRELATED_MIN_UA_MISMATCH_PCT, String.valueOf(clampPct(next.correlatedMinUaMismatchRatioPct())), "UA Pillar 2 min UA mismatch request %", actor);

		settingsRepository.setSetting(KEY_DATACENTER_MIN_REQUESTS, String.valueOf(Math.max(1L, next.datacenterMinRequests())), "UA Pillar 3 datacenter scraper min requests", actor);
		settingsRepository.setSetting(KEY_DATACENTER_MIN_RATIO_PCT, String.valueOf(clampPct(next.datacenterMinRatioPct())), "UA Pillar 3 datacenter request min %", actor);

		log.info("Updated User-Agent 3-pillar heuristic settings by '{}' (spread={} reqs/{} subs/{} ASNs)",
				actor, next.spreadMinRequests(), next.spreadMinSubnets(), next.spreadMinAsns());
		EffectiveUaHeuristicSettings effective = getEffectiveSettings();
		if (properties.getMode().isBackgroundProcessingEnabled() && jdbcTemplate != null) {
			try {
				refreshProfiles24h();
			} catch (Exception e) {
				log.debug("Deferred UA profile refresh after settings update: {}", e.getMessage());
			}
		}
		return effective;
	}

	public EffectiveUaHeuristicSettings resetToDefaults(String updatedBy) {
		if (!properties.canPerformSystemAdmin() || CollectorAuthContext.isAiAgent()) {
			throw new IllegalStateException("Resetting User-Agent heuristic thresholds requires FULL admin mode.");
		}
		if (settingsRepository != null) {
			for (String key : ALL_SETTING_KEYS) {
				settingsRepository.deleteSetting(key);
			}
		}
		log.info("Reset User-Agent 3-pillar heuristic settings to YAML defaults by '{}'", updatedBy);
		if (properties.getMode().isBackgroundProcessingEnabled() && jdbcTemplate != null) {
			try {
				refreshProfiles24h();
			} catch (Exception ignored) {
			}
		}
		return getEffectiveSettings();
	}

	public void updateManualOverride(
			String rawUserAgent,
			UserAgentManualOverride override,
			String operatorNote,
			String updatedBy
	) {
		if (!properties.canModifyOperationalData() || CollectorAuthContext.isAiAgent()) {
			throw new IllegalStateException("Modifying User-Agent manual overrides is disabled in " + properties.getMode() + " mode.");
		}
		if (rawUserAgent == null || rawUserAgent.isBlank()) {
			throw new IllegalArgumentException("User-Agent string must not be empty.");
		}
		String trimmed = rawUserAgent.trim();
		UserAgentFamily family = UserAgentClassifier.classify(trimmed);
		Integer major = null;
		if (browserVersionSyncService != null) {
			major = browserVersionSyncService.assessUserAgent(family, trimmed).parsedMajorVersion();
		}
		String actor = updatedBy != null && !updatedBy.isBlank() ? updatedBy : CollectorAuthContext.getEffectiveActor("ADMIN");
		memoryRepository.updateManualOverride(trimmed, family, major, override, operatorNote, actor);
		log.info("User-Agent manual override set by '{}': override={}, ua='{}'", actor, override, trimmed);
	}

	public Map<String, UserAgentProfile> getProfilesMap(List<String> rawUserAgents) {
		if (memoryRepository == null || rawUserAgents == null || rawUserAgents.isEmpty()) {
			return Map.of();
		}
		try {
			return memoryRepository.findProfilesByRawUserAgents(rawUserAgents);
		} catch (Exception e) {
			return Map.of();
		}
	}

	public Map<String, UserAgentProfile> getAllManualOverrides() {
		if (memoryRepository == null) {
			return Map.of();
		}
		try {
			return memoryRepository.findAllManualOverrides();
		} catch (Exception e) {
			return Map.of();
		}
	}

	public EvaluationOutcome evaluateVerdict(EvaluationInput in, EffectiveUaHeuristicSettings cfg) {
		EffectiveUaHeuristicSettings s = cfg != null ? cfg : getEffectiveSettings();
		UserAgentFamily family = in.family() != null ? in.family() : UserAgentClassifier.classify(in.userAgent());
		long totalReqs = Math.max(0L, in.totalRequests());
		int evCount = Math.max(0, in.eventCount());

		double internalRatioPct = totalReqs > 0 ? round1(in.internalRequests() * 100.0 / totalReqs) : 0.0;
		double searchEngineRatioPct = totalReqs > 0 ? round1(in.searchEngineRequests() * 100.0 / totalReqs) : 0.0;
		double sampleAuthRatioPct = evCount > 0 ? round2(in.authSamples() * 100.0 / evCount) : 0.0;
		double slotAuthRatioPct = totalReqs > 0 ? round2(in.authRequests() * 100.0 / totalReqs) : 0.0;
		double incidentEventRatioPct = evCount > 0 ? round1((in.blockedEvents() + in.markedEvents()) * 100.0 / evCount) : 0.0;
		double mitigatedAsnRatioPct = totalReqs > 0 ? round1(in.mitigatedAsnRequests() * 100.0 / totalReqs) : 0.0;
		double uaMismatchRatioPct = totalReqs > 0 ? round1(in.uaMismatchRequests() * 100.0 / totalReqs) : 0.0;
		double datacenterRatioPct = totalReqs > 0 ? round1(in.datacenterRequests() * 100.0 / totalReqs) : 0.0;
		double residentialRatioPct = totalReqs > 0 ? round1(in.residentialRequests() * 100.0 / totalReqs) : 0.0;
		double avgSlotReqs = evCount > 0 ? round1(totalReqs * 1.0 / evCount) : 0.0;

		BrowserVersionLagAssessment versionAssessment = BrowserVersionLagAssessment.UNTRACKED;
		Integer parsedMajor = null;
		Integer versionLag = null;
		String browserFamLabel = family.displayName();
		if (browserVersionSyncService != null) {
			var vRes = browserVersionSyncService.assessUserAgent(family, in.userAgent());
			versionAssessment = vRes.assessment();
			parsedMajor = vRes.parsedMajorVersion();
			versionLag = vRes.versionLagMajors();
			browserFamLabel = vRes.browserFamily();
		}

		long externalReqs = Math.max(0L, totalReqs - in.internalRequests() - in.searchEngineRequests());
		boolean resZeroAuth = residentialRatioPct >= 50.0 && in.residentialRequests() >= 50L
				&& in.authSamples() == 0 && sampleAuthRatioPct < s.authImmunityMinSampleRatioPct();

		// Stage 0a: Internal / Private Network Immunity (Room displays, campus scripts, internal apps)
		if (in.internalRequests() >= s.internalImmunityMinRequests()
				|| (totalReqs > 0 && internalRatioPct >= s.internalImmunityMinRatioPct() && in.internalRequests() > 0)) {
			String reason = String.format(Locale.ROOT,
					"Internal / private network share %.1f%% (%d reqs) — exempt from negative heuristics",
					internalRatioPct, in.internalRequests());
			return buildOutcome(UserAgentAutoVerdict.IMMUNE_INTERNAL, reason, versionAssessment, parsedMajor, versionLag,
					internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
					mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, false);
		}

		// Stage 0b: Verified Search Engine Immunity
		if (searchEngineRatioPct >= s.searchEngineImmunityMinRatioPct() && in.searchEngineRequests() > 0) {
			String reason = String.format(Locale.ROOT,
					"Verified search engine IP feed share %.1f%% (%d reqs)",
					searchEngineRatioPct, in.searchEngineRequests());
			return buildOutcome(UserAgentAutoVerdict.IMMUNE_SEARCH_ENGINE, reason, versionAssessment, parsedMajor, versionLag,
					internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
					mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, false);
		}

		// Stage 0c: Authenticated User / Mobile App Immunity
		boolean authSampleImmune = in.authSamples() >= 2 && sampleAuthRatioPct >= s.authImmunityMinSampleRatioPct();
		boolean authSlotImmune = in.authRequests() >= 10 && slotAuthRatioPct >= s.authImmunityMinSlotRatioPct();
		if (authSampleImmune || authSlotImmune) {
			String reason = String.format(Locale.ROOT,
					"Authenticated traffic immunity (sample auth %.2f%% [%d samples], slot auth %.2f%%)",
					sampleAuthRatioPct, in.authSamples(), slotAuthRatioPct);
			return buildOutcome(UserAgentAutoVerdict.IMMUNE_AUTHENTICATED, reason, versionAssessment, parsedMajor, versionLag,
					internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
					mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, false);
		}

		// Pillar 1: Ultra-Spread Proxy Botnet
		boolean spreadScale = externalReqs >= s.spreadMinRequests()
				&& in.distinctSubnets() >= s.spreadMinSubnets()
				&& in.distinctAsns() >= s.spreadMinAsns();
		boolean spreadBehaviorOrLag = avgSlotReqs <= s.spreadMaxAvgSlotRequests()
				|| (versionLag != null && versionLag >= s.spreadMinVersionLagMajors());
		if (spreadScale && spreadBehaviorOrLag) {
			String reason = String.format(Locale.ROOT,
					"Pillar 1 (Ultra-Spread): %d external reqs across %d subnets / %d ASNs (avg %.1f reqs/slot%s, %.2f%% auth)",
					externalReqs, in.distinctSubnets(), in.distinctAsns(), avgSlotReqs,
					(versionLag != null && versionLag >= s.spreadMinVersionLagMajors()) ? ", lag -" + versionLag + "v" : "",
					sampleAuthRatioPct);
			return buildOutcome(UserAgentAutoVerdict.SUSPICIOUS_ULTRA_SPREAD, reason, versionAssessment, parsedMajor, versionLag,
					internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
					mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, resZeroAuth);
		}

		// Pillar 2: Guilt by Association (Mitigation / Incident / UA-Mismatch Correlated)
		if (externalReqs >= s.correlatedMinRequests()) {
			List<String> corrTriggers = new ArrayList<>();
			if (incidentEventRatioPct >= s.correlatedMinIncidentRatioPct()) {
				corrTriggers.add(String.format(Locale.ROOT, "incidents %.1f%%", incidentEventRatioPct));
			}
			if (mitigatedAsnRatioPct >= s.correlatedMinMitigatedAsnRatioPct() || in.mitigationOriginMatch()) {
				if (mitigatedAsnRatioPct >= s.correlatedMinMitigatedAsnRatioPct()) {
					corrTriggers.add(String.format(Locale.ROOT, "mitigated ASNs %.1f%%", mitigatedAsnRatioPct));
				} else if (in.mitigationOriginMatch() && incidentEventRatioPct >= 10.0) {
					corrTriggers.add(in.mitigationMatchDetails() != null ? in.mitigationMatchDetails() : "mitigated origin");
				}
			}
			if (uaMismatchRatioPct >= s.correlatedMinUaMismatchRatioPct()) {
				corrTriggers.add(String.format(Locale.ROOT, "UA mismatch %.1f%%", uaMismatchRatioPct));
			}
			if (!corrTriggers.isEmpty()) {
				String reason = String.format(Locale.ROOT,
						"Pillar 2 (Correlated): %d external reqs (%s)", externalReqs, String.join(", ", corrTriggers));
				return buildOutcome(UserAgentAutoVerdict.SUSPICIOUS_CORRELATED, reason, versionAssessment, parsedMajor, versionLag,
						internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
						mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, resZeroAuth);
			}
		}

		// Pillar 3: Datacenter Zero-Auth Scraper
		if (externalReqs >= s.datacenterMinRequests()
				&& in.authSamples() == 0
				&& datacenterRatioPct >= s.datacenterMinRatioPct()) {
			String reason = String.format(Locale.ROOT,
					"Pillar 3 (Datacenter Zero-Auth): %d external reqs, %.1f%% datacenter, 0 auth samples",
					externalReqs, datacenterRatioPct);
			return buildOutcome(UserAgentAutoVerdict.SUSPICIOUS_DATACENTER, reason, versionAssessment, parsedMajor, versionLag,
					internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
					mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, resZeroAuth);
		}

		// Signature / Version Anomaly / Low-Volume Hostile Signals
		List<String> sigReasons = new ArrayList<>();
		if (family == UserAgentFamily.EMPTY) {
			sigReasons.add("Empty User-Agent header");
		} else if (family.isAutomated()) {
			sigReasons.add(family == UserAgentFamily.BOT_CRAWLER ? "Crawler signature" : "Scraper / tool library signature");
		}
		if (versionAssessment == BrowserVersionLagAssessment.IMPLAUSIBLE_FUTURE) {
			sigReasons.add(String.format(Locale.ROOT, "Implausible future version (%s v%s)", browserFamLabel, parsedMajor));
		} else if (versionAssessment == BrowserVersionLagAssessment.FORGED_BUILD_ANOMALY) {
			sigReasons.add(String.format(Locale.ROOT, "Forged browser build number (%s v%s non-zero build/patch)", browserFamLabel, parsedMajor));
		} else if (versionAssessment == BrowserVersionLagAssessment.OBSOLETE_ANOMALY) {
			sigReasons.add(String.format(Locale.ROOT, "Obsolete browser version (%s v%s, -%s lag)", browserFamLabel, parsedMajor, versionLag));
		}
		if (incidentEventRatioPct >= 50.0 && (in.blockedEvents() + in.markedEvents()) >= 2) {
			sigReasons.add(String.format(Locale.ROOT, "High incident rate (%.1f%% blocked/marked)", incidentEventRatioPct));
		}
		if (in.mitigationOriginMatch() && (in.authSamples() == 0)) {
			sigReasons.add(in.mitigationMatchDetails() != null ? in.mitigationMatchDetails() : "Origin in mitigated network");
		}

		if (!sigReasons.isEmpty()) {
			return buildOutcome(UserAgentAutoVerdict.SUSPICIOUS_SIGNATURE, String.join(" • ", sigReasons),
					versionAssessment, parsedMajor, versionLag,
					internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
					mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, resZeroAuth);
		}

		// Fallback legacy auth tag if any auth exists below formal immunity threshold
		if (in.authSamples() > 0 || in.authRequests() > 0) {
			String reason = String.format(Locale.ROOT,
					"Standard traffic (%d auth samples, below threshold for immunity or suspicion)", in.authSamples());
			return buildOutcome(UserAgentAutoVerdict.NEUTRAL, reason, versionAssessment, parsedMajor, versionLag,
					internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
					mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, false);
		}

		return buildOutcome(UserAgentAutoVerdict.NEUTRAL, "Below heuristic thresholds",
				versionAssessment, parsedMajor, versionLag,
				internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct, incidentEventRatioPct,
				mitigatedAsnRatioPct, uaMismatchRatioPct, datacenterRatioPct, residentialRatioPct, avgSlotReqs, resZeroAuth);
	}

	private static EvaluationOutcome buildOutcome(
			UserAgentAutoVerdict verdict,
			String reason,
			BrowserVersionLagAssessment versionAssessment,
			Integer parsedMajor,
			Integer versionLag,
			double internalRatioPct,
			double searchEngineRatioPct,
			double sampleAuthRatioPct,
			double slotAuthRatioPct,
			double incidentEventRatioPct,
			double mitigatedAsnRatioPct,
			double uaMismatchRatioPct,
			double datacenterRatioPct,
			double residentialRatioPct,
			double avgSlotReqs,
			boolean resZeroAuth
	) {
		return new EvaluationOutcome(
				verdict, reason, versionAssessment, parsedMajor, versionLag,
				internalRatioPct, searchEngineRatioPct, sampleAuthRatioPct, slotAuthRatioPct,
				incidentEventRatioPct, mitigatedAsnRatioPct, uaMismatchRatioPct,
				datacenterRatioPct, residentialRatioPct, avgSlotReqs, resZeroAuth
		);
	}

	/**
	 * Aggregates a single time bucket (typically 60 min) of User-Agent telemetry from {@code client_events}
	 * into {@code user_agent_hourly_rollups} and ensures profiles exist in {@code dim_user_agent}.
	 */
	public int aggregateHourlyWindow(Instant bucketStart, Instant bucketEnd) {
		if (!properties.getMode().isBackgroundProcessingEnabled() || jdbcTemplate == null || memoryRepository == null) {
			return 0;
		}
		if (bucketStart == null || bucketEnd == null || !bucketEnd.isAfter(bucketStart)) {
			return 0;
		}

		EffectiveUaHeuristicSettings cfg = getEffectiveSettings();
		Set<Long> mitigatedAsns = loadActiveOrRecentMitigatedAsns(bucketStart.minus(24, ChronoUnit.HOURS), bucketEnd);
		String mitAsnInClause = buildNumericAsnInClause(mitigatedAsns);

		String mitExpr = mitAsnInClause != null
				? "SUM(CASE WHEN asn IN (" + mitAsnInClause + ") THEN request_count ELSE 0 END) AS mitigated_asn_requests"
				: "0 AS mitigated_asn_requests";

		String sql = """
				SELECT
				    TRIM(sample_user_agent) AS ua,
				    SUM(request_count) AS total_requests,
				    COUNT(*) AS event_count,
				    SUM(CASE WHEN status = 'BLOCKED' THEN request_count ELSE 0 END) AS blocked_requests,
				    SUM(CASE WHEN status = 'MARKED' THEN request_count ELSE 0 END) AS marked_requests,
				    SUM(CASE WHEN status IN ('BLOCKED', 'MARKED') THEN 1 ELSE 0 END) AS incident_events,
				    SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked_events,
				    SUM(CASE WHEN status = 'MARKED' THEN 1 ELSE 0 END) AS marked_events,
				    SUM(CASE WHEN sample_authenticated = TRUE THEN 1 ELSE 0 END) AS auth_samples,
				    SUM(COALESCE(authenticated_count, 0)) AS auth_requests,
				    SUM(CASE WHEN client_type IN ('PRIVATE_NETWORK', 'INTERNAL_NETWORK') THEN request_count ELSE 0 END) AS internal_requests,
				    SUM(CASE WHEN client_type = 'SEARCH_ENGINE' THEN request_count ELSE 0 END) AS search_engine_requests,
				    SUM(CASE WHEN client_type IN ('SEARCH_ENGINE', 'AI_CRAWLER') THEN request_count ELSE 0 END) AS crawler_requests,
				    SUM(CASE WHEN client_type IN ('DATACENTER', 'TOR_EXIT_NODE') THEN request_count ELSE 0 END) AS datacenter_requests,
				    SUM(CASE WHEN client_type IN ('RESIDENTIAL', 'PRIVACY_RELAY') THEN request_count ELSE 0 END) AS residential_requests,
				    SUM(COALESCE(returning_count, 0)) AS returning_requests,
				    SUM(COALESCE(ua_mismatch_count, 0)) AS ua_mismatch_requests,
				    COUNT(DISTINCT NULLIF(subnet_group, '')) AS distinct_subnets,
				    COUNT(DISTINCT asn) AS distinct_asns,
				""" + mitExpr + """
				
				FROM client_events
				WHERE slot_time >= ? AND slot_time < ?
				  AND sample_user_agent IS NOT NULL
				  AND TRIM(sample_user_agent) != ''
				GROUP BY TRIM(sample_user_agent)
				""";

		record BucketUaRow(
				String ua, String hash, int hash32, UserAgentFamily family, Integer majorVer,
				long totalReqs, int eventCount, long blockedReqs, long markedReqs, int incidentEvents,
				int blockedEvents, int markedEvents, int authSamples, long authReqs,
				long internalReqs, long searchEngineReqs, long crawlerReqs,
				long dcReqs, long resReqs, long retReqs, long mmReqs, long mitAsnReqs,
				int subnets, int asns, EvaluationOutcome eval
		) {}

		List<BucketUaRow> parsed = new ArrayList<>();
		List<UserAgentMemoryRepository.ProfileSeed> seeds = new ArrayList<>();

		jdbcTemplate.query(sql, rs -> {
			String ua = rs.getString("ua");
			if (ua == null || ua.isBlank()) return;
			UserAgentFamily fam = UserAgentClassifier.classify(ua);
			long totalReqs = rs.getLong("total_requests");
			int eventCount = rs.getInt("event_count");
			int blockedEvents = rs.getInt("blocked_events");
			int markedEvents = rs.getInt("marked_events");
			int subnets = rs.getInt("distinct_subnets");
			int asns = rs.getInt("distinct_asns");
			int authSamples = rs.getInt("auth_samples");
			long authReqs = rs.getLong("auth_requests");
			long internalReqs = rs.getLong("internal_requests");
			long seReqs = rs.getLong("search_engine_requests");
			long crawlerReqs = rs.getLong("crawler_requests");
			long dcReqs = rs.getLong("datacenter_requests");
			long resReqs = rs.getLong("residential_requests");
			long mitAsnReqs = rs.getLong("mitigated_asn_requests");
			long mmReqs = rs.getLong("ua_mismatch_requests");

			EvaluationOutcome eval = evaluateVerdict(new EvaluationInput(
					ua, fam, totalReqs, eventCount, blockedEvents, markedEvents,
					subnets, asns, authSamples, authReqs, internalReqs, seReqs,
					dcReqs, resReqs, mitAsnReqs, mmReqs, false, null
			), cfg);

			String hash = UserAgentMemoryRepository.computeSha256Hex(ua);
			int hash32 = UserAgentMemoryRepository.computeUaHash32(ua);

			seeds.add(new UserAgentMemoryRepository.ProfileSeed(
					hash, hash32, ua, fam, eval.parsedMajorVersion(), bucketEnd
			));
			parsed.add(new BucketUaRow(
					ua, hash, hash32, fam, eval.parsedMajorVersion(),
					totalReqs, eventCount, rs.getLong("blocked_requests"), rs.getLong("marked_requests"),
					rs.getInt("incident_events"), blockedEvents, markedEvents, authSamples, authReqs,
					internalReqs, seReqs, crawlerReqs, dcReqs, resReqs, rs.getLong("returning_requests"),
					mmReqs, mitAsnReqs, subnets, asns, eval
			));
		}, Timestamp.from(bucketStart), Timestamp.from(bucketEnd));

		if (parsed.isEmpty()) {
			return 0;
		}

		Map<String, Long> idByHash = memoryRepository.ensureProfilesBatch(seeds);
		List<UserAgentMemoryRepository.HourlyRollupWrite> rollups = new ArrayList<>(parsed.size());
		for (BucketUaRow r : parsed) {
			Long uaId = idByHash.get(r.hash());
			if (uaId == null || uaId <= 0) continue;
			rollups.add(new UserAgentMemoryRepository.HourlyRollupWrite(
					bucketStart,
					bucketEnd,
					uaId,
					r.totalReqs(),
					r.eventCount(),
					r.blockedReqs(),
					r.markedReqs(),
					r.incidentEvents(),
					r.authSamples(),
					r.authReqs(),
					r.internalReqs(),
					r.crawlerReqs(),
					r.dcReqs(),
					r.resReqs(),
					r.retReqs(),
					r.mmReqs(),
					r.subnets(),
					r.asns(),
					r.eval().verdict(),
					r.eval().verdict().pillarCode(),
					r.eval().reason()
			));
		}
		memoryRepository.batchUpsertHourlyRollups(rollups);
		return rollups.size();
	}

	/**
	 * Recomputes 24-hour and retained lifetime User-Agent profiles in {@code dim_user_agent}
	 * from {@code user_agent_hourly_rollups}, updating {@code auto_verdict} while strictly
	 * preserving {@code manual_override} and {@code operator_note}.
	 */
	public int refreshProfiles24h() {
		if (!properties.getMode().isBackgroundProcessingEnabled() || jdbcTemplate == null || memoryRepository == null) {
			return 0;
		}
		Instant now = Instant.now();
		Instant cutoff24h = now.minus(24, ChronoUnit.HOURS);
		EffectiveUaHeuristicSettings cfg = getEffectiveSettings();

		// Fetch exact 24h mitigated ASN volumes if available from raw client_events
		Set<Long> mitigatedAsns = loadActiveOrRecentMitigatedAsns(cutoff24h, now);
		Map<String, MitigatedAndSpread24h> exact24hExtras = loadExact24hSpreadAndMitigation(cutoff24h, now, mitigatedAsns);

		String aggSql = """
				SELECT
				    d.id,
				    d.user_agent_hash,
				    d.ua_hash_32,
				    d.raw_user_agent,
				    d.browser_family,
				    d.parsed_major_version,
				    d.first_seen_at,
				    d.manual_override,
				    d.operator_note,
				    d.updated_by,
				    d.updated_at,
				    MIN(r.bucket_start) AS min_bucket,
				    MAX(r.bucket_end) AS max_bucket,
				    SUM(r.total_requests) AS life_reqs,
				    SUM(r.blocked_requests) AS life_blk,
				    SUM(r.marked_requests) AS life_mrk,
				    SUM(r.authenticated_samples) AS life_auth_samples,
				    SUM(r.authenticated_requests) AS life_auth_reqs,
				    SUM(r.internal_requests) AS life_internal_reqs,
				    SUM(r.crawler_requests) AS life_crawler_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.total_requests ELSE 0 END) AS r24_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.event_count ELSE 0 END) AS r24_events,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.blocked_requests ELSE 0 END) AS r24_blk_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.marked_requests ELSE 0 END) AS r24_mrk_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.incident_events ELSE 0 END) AS r24_inc_events,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.authenticated_samples ELSE 0 END) AS r24_auth_samples,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.authenticated_requests ELSE 0 END) AS r24_auth_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.internal_requests ELSE 0 END) AS r24_internal_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.crawler_requests ELSE 0 END) AS r24_crawler_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.datacenter_requests ELSE 0 END) AS r24_dc_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.residential_requests ELSE 0 END) AS r24_res_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.returning_requests ELSE 0 END) AS r24_ret_reqs,
				    SUM(CASE WHEN r.bucket_start >= ? THEN r.ua_mismatch_requests ELSE 0 END) AS r24_mm_reqs,
				    MAX(CASE WHEN r.bucket_start >= ? THEN r.distinct_subnets ELSE 0 END) AS r24_max_sub,
				    MAX(CASE WHEN r.bucket_start >= ? THEN r.distinct_asns ELSE 0 END) AS r24_max_asn
				FROM dim_user_agent d
				JOIN user_agent_hourly_rollups r ON r.ua_id = d.id
				GROUP BY d.id, d.user_agent_hash, d.ua_hash_32, d.raw_user_agent, d.browser_family,
				         d.parsed_major_version, d.first_seen_at, d.manual_override, d.operator_note,
				         d.updated_by, d.updated_at
				""";

		Timestamp ts24 = Timestamp.from(cutoff24h);
		Object[] params = new Object[] { ts24, ts24, ts24, ts24, ts24, ts24, ts24, ts24, ts24, ts24, ts24, ts24, ts24, ts24, ts24 };

		List<UserAgentProfile> updates = new ArrayList<>();
		jdbcTemplate.query(aggSql, rs -> {
			String rawUa = rs.getString("raw_user_agent");
			UserAgentFamily fam = UserAgentClassifier.classify(rawUa);
			Integer majorVer = rs.getObject("parsed_major_version") != null ? rs.getInt("parsed_major_version") : null;
			Timestamp firstSeenTs = rs.getTimestamp("first_seen_at");
			Timestamp minBucketTs = rs.getTimestamp("min_bucket");
			Timestamp maxBucketTs = rs.getTimestamp("max_bucket");

			Instant firstSeen = firstSeenTs != null ? firstSeenTs.toInstant() : now;
			if (minBucketTs != null && minBucketTs.toInstant().isBefore(firstSeen)) {
				firstSeen = minBucketTs.toInstant();
			}
			Instant lastSeen = maxBucketTs != null ? maxBucketTs.toInstant() : now;

			long r24Reqs = rs.getLong("r24_reqs");
			int r24Events = rs.getInt("r24_events");
			long r24Blk = rs.getLong("r24_blk_reqs");
			long r24Mrk = rs.getLong("r24_mrk_reqs");
			int r24IncEvents = rs.getInt("r24_inc_events");
			int r24AuthSamples = rs.getInt("r24_auth_samples");
			long r24AuthReqs = rs.getLong("r24_auth_reqs");
			long r24InternalReqs = rs.getLong("r24_internal_reqs");
			long r24CrawlerReqs = rs.getLong("r24_crawler_reqs");
			long r24DcReqs = rs.getLong("r24_dc_reqs");
			long r24ResReqs = rs.getLong("r24_res_reqs");
			long r24RetReqs = rs.getLong("r24_ret_reqs");
			long r24MmReqs = rs.getLong("r24_mm_reqs");

			MitigatedAndSpread24h exact = exact24hExtras.get(rawUa);
			int subnets = exact != null ? Math.max(exact.distinctSubnets(), rs.getInt("r24_max_sub")) : rs.getInt("r24_max_sub");
			int asns = exact != null ? Math.max(exact.distinctAsns(), rs.getInt("r24_max_asn")) : rs.getInt("r24_max_asn");
			long mitAsnReqs = exact != null ? exact.mitigatedAsnRequests() : 0L;
			long seReqs = exact != null ? exact.searchEngineRequests() : 0L;

			int approxBlockedEv = (r24Blk > 0 && r24IncEvents > 0) ? r24IncEvents : 0;
			EvaluationOutcome eval = evaluateVerdict(new EvaluationInput(
					rawUa, fam, r24Reqs, r24Events, approxBlockedEv, 0,
					subnets, asns, r24AuthSamples, r24AuthReqs, r24InternalReqs, seReqs,
					r24DcReqs, r24ResReqs, mitAsnReqs, r24MmReqs, false, null
			), cfg);

			updates.add(new UserAgentProfile(
					rs.getLong("id"),
					rs.getString("user_agent_hash"),
					rs.getInt("ua_hash_32"),
					rawUa,
					fam,
					eval.parsedMajorVersion() != null ? eval.parsedMajorVersion() : majorVer,
					fam.isAutomated(),
					firstSeen,
					lastSeen,
					rs.getLong("life_reqs"),
					rs.getLong("life_blk"),
					rs.getLong("life_mrk"),
					rs.getLong("life_auth_samples"),
					rs.getLong("life_auth_reqs"),
					rs.getLong("life_internal_reqs"),
					rs.getLong("life_crawler_reqs"),
					r24Reqs,
					r24Events,
					r24Blk,
					r24Mrk,
					subnets,
					asns,
					r24AuthSamples,
					r24AuthReqs,
					r24InternalReqs,
					r24CrawlerReqs,
					r24DcReqs,
					r24ResReqs,
					r24RetReqs,
					r24MmReqs,
					eval.verdict(),
					eval.verdict().pillarCode(),
					eval.reason(),
					now,
					UserAgentManualOverride.fromString(rs.getString("manual_override")),
					rs.getString("operator_note"),
					rs.getString("updated_by"),
					now
			));
		}, params);

		if (!updates.isEmpty()) {
			memoryRepository.batchUpdateProfilesPreservingOverrides(updates);
		}
		log.debug("Refreshed {} User-Agent profiles in dim_user_agent", updates.size());
		return updates.size();
	}

	/**
	 * Backfills UA hourly rollups and profiles when {@code dim_user_agent} is still empty
	 * on an existing database containing raw {@code client_events}.
	 */
	public void backfillIfEmpty() {
		if (!properties.getMode().isBackgroundProcessingEnabled()
				|| jdbcTemplate == null || memoryRepository == null
				|| !initialBackfillChecked.compareAndSet(false, true)) {
			return;
		}
		try {
			if (memoryRepository.countHourlyRollups() > 0) {
				return;
			}
			Instant latest = clientEventRepository != null ? clientEventRepository.findLatestSlotTime().orElse(null) : null;
			if (latest == null) {
				return;
			}
			Instant endHour = latest.truncatedTo(ChronoUnit.HOURS).plus(1, ChronoUnit.HOURS);
			Instant startHour = endHour.minus(24, ChronoUnit.HOURS);
			int totalRows = 0;
			for (Instant b = startHour; b.isBefore(endHour); b = b.plus(1, ChronoUnit.HOURS)) {
				totalRows += aggregateHourlyWindow(b, b.plus(1, ChronoUnit.HOURS));
			}
			if (totalRows > 0) {
				int refreshed = refreshProfiles24h();
				log.info("Backfilled {} User-Agent hourly rollups and {} profiles from existing client_events",
						totalRows, refreshed);
			}
		} catch (Exception e) {
			log.warn("Initial User-Agent memory backfill encountered an issue: {}", e.getMessage());
		}
	}

	public int cleanupOldHourlyRollups() {
		if (!properties.getMode().isBackgroundProcessingEnabled() || memoryRepository == null) {
			return 0;
		}
		int retentionDays = Math.max(1, properties.getRollupRetentionDays());
		Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
		return memoryRepository.deleteHourlyRollupsOlderThan(cutoff);
	}

	/**
	 * Builds the full forensic drilldown model for a single User-Agent, including manual override
	 * status vs. live 3-pillar evaluation, top origins, and chronological hourly evaluation history.
	 * Safe to invoke in all modes including {@code VIEWER} (never performs writes).
	 */
	public UserAgentDrilldownDto getUserAgentDrilldown(String rawUserAgent, int hours) {
		String trimmed = rawUserAgent != null ? rawUserAgent.trim() : "";
		int safeHours = Math.max(1, Math.min(720, hours > 0 ? hours : 168));
		Instant now = Instant.now();
		Instant from = now.minus(safeHours, ChronoUnit.HOURS);

		EffectiveUaHeuristicSettings cfg = getEffectiveSettings();
		UserAgentFamily family = UserAgentClassifier.classify(trimmed);
		Optional<UserAgentProfile> existingProfile = memoryRepository != null
				? memoryRepository.findByRawUserAgent(trimmed)
				: Optional.empty();

		String shaHash = existingProfile.map(UserAgentProfile::userAgentHash)
				.orElseGet(() -> UserAgentMemoryRepository.computeSha256Hex(trimmed));
		int hash32 = existingProfile.map(UserAgentProfile::uaHash32)
				.orElseGet(() -> UserAgentMemoryRepository.computeUaHash32(trimmed));

		UserAgentManualOverride manualOverride = existingProfile
				.map(UserAgentProfile::effectiveOverride)
				.orElse(UserAgentManualOverride.AUTO);
		String operatorNote = existingProfile.map(UserAgentProfile::operatorNote).orElse(null);
		String updatedBy = existingProfile.map(UserAgentProfile::updatedBy).orElse(null);
		Instant updatedAt = existingProfile.map(UserAgentProfile::updatedAt).orElse(null);

		List<UserAgentHourlyPoint> hourlyHistory = new ArrayList<>();
		boolean historyFromLiveEvents = false;

		if (existingProfile.isPresent() && existingProfile.get().id() != null && memoryRepository != null) {
			hourlyHistory = memoryRepository.findHourlyHistoryByUaId(existingProfile.get().id(), from, now);
		}

		if (hourlyHistory.isEmpty() && jdbcTemplate != null) {
			// Fall back to live hourly aggregation directly from client_events (works cleanly in VIEWER mode too!)
			hourlyHistory = queryLiveHourlyHistory(trimmed, family, from, now, cfg);
			historyFromLiveEvents = true;
		}

		// Compute aggregate metrics over the drilldown lookback window
		long totalReqs = 0L;
		int eventCount = 0;
		long blockedReqs = 0L;
		long markedReqs = 0L;
		int incidentEvents = 0;
		int authSamples = 0;
		long authReqs = 0L;
		long internalReqs = 0L;
		long crawlerReqs = 0L;
		long dcReqs = 0L;
		long resReqs = 0L;
		long mmReqs = 0L;
		int maxHourlySubnets = 0;
		int maxHourlyAsns = 0;

		for (UserAgentHourlyPoint pt : hourlyHistory) {
			totalReqs += pt.totalRequests();
			eventCount += pt.eventCount();
			blockedReqs += pt.blockedRequests();
			markedReqs += pt.markedRequests();
			incidentEvents += pt.incidentEvents();
			authSamples += pt.authenticatedSamples();
			authReqs += pt.authenticatedRequests();
			internalReqs += pt.internalRequests();
			crawlerReqs += pt.crawlerRequests();
			dcReqs += pt.datacenterRequests();
			resReqs += pt.residentialRequests();
			mmReqs += pt.uaMismatchRequests();
			if (pt.distinctSubnets() > maxHourlySubnets) maxHourlySubnets = pt.distinctSubnets();
			if (pt.distinctAsns() > maxHourlyAsns) maxHourlyAsns = pt.distinctAsns();
		}

		// Merge exact spread & mitigated ASN stats from live client_events if available
		Set<Long> mitigatedAsns = loadActiveOrRecentMitigatedAsns(from, now);
		ExactSingleUaMetrics liveSingle = loadExactSingleUaMetrics(trimmed, from, now, mitigatedAsns);
		if (liveSingle != null && liveSingle.totalRequests() > 0) {
			totalReqs = Math.max(totalReqs, liveSingle.totalRequests());
			eventCount = Math.max(eventCount, liveSingle.eventCount());
			maxHourlySubnets = Math.max(maxHourlySubnets, liveSingle.distinctSubnets());
			maxHourlyAsns = Math.max(maxHourlyAsns, liveSingle.distinctAsns());
			if (liveSingle.internalRequests() > internalReqs) internalReqs = liveSingle.internalRequests();
			if (liveSingle.authSamples() > authSamples) authSamples = liveSingle.authSamples();
			if (liveSingle.authRequests() > authReqs) authReqs = liveSingle.authRequests();
		}

		long mitigatedAsnReqs = liveSingle != null ? liveSingle.mitigatedAsnRequests() : 0L;
		long seReqs = liveSingle != null ? liveSingle.searchEngineRequests() : 0L;

		List<UserAgentOriginSummary> topOrigins = clientEventRepository != null
				? clientEventRepository.findUserAgentTopOrigins(trimmed, from, now, null, null, 8)
				: List.of();

		EvaluationOutcome liveEval = evaluateVerdict(new EvaluationInput(
				trimmed, family, totalReqs, eventCount, incidentEvents, 0,
				maxHourlySubnets, maxHourlyAsns, authSamples, authReqs,
				internalReqs, seReqs, dcReqs, resReqs, mitigatedAsnReqs, mmReqs,
				false, null
		), cfg);

		final List<UserAgentHourlyPoint> finalHourlyHistory = hourlyHistory;
		Instant firstSeen = existingProfile.map(UserAgentProfile::firstSeenAt)
				.orElseGet(() -> finalHourlyHistory.stream()
						.map(UserAgentHourlyPoint::bucketStart)
						.min(Comparator.naturalOrder())
						.orElse(null));
		Instant lastSeen = existingProfile.map(UserAgentProfile::lastSeenAt)
				.orElseGet(() -> finalHourlyHistory.stream()
						.map(UserAgentHourlyPoint::bucketEnd)
						.max(Comparator.naturalOrder())
						.orElse(null));

		return new UserAgentDrilldownDto(
				trimmed,
				shaHash,
				hash32,
				family,
				liveEval.versionAssessment(),
				liveEval.parsedMajorVersion(),
				liveEval.versionLagMajors(),
				firstSeen,
				lastSeen,
				safeHours,
				manualOverride,
				operatorNote,
				updatedBy,
				updatedAt,
				liveEval.verdict(),
				liveEval.reason(),
				totalReqs,
				eventCount,
				blockedReqs,
				markedReqs,
				maxHourlySubnets,
				maxHourlyAsns,
				liveEval.internalRatioPct(),
				internalReqs,
				liveEval.searchEngineRatioPct(),
				liveEval.sampleAuthRatioPct(),
				authSamples,
				liveEval.slotAuthRatioPct(),
				authReqs,
				liveEval.incidentEventRatioPct(),
				liveEval.mitigatedAsnRatioPct(),
				liveEval.uaMismatchRatioPct(),
				liveEval.datacenterRatioPct(),
				liveEval.avgRequestsPerSlot(),
				cfg,
				topOrigins,
				hourlyHistory,
				historyFromLiveEvents
		);
	}

	private List<UserAgentHourlyPoint> queryLiveHourlyHistory(
			String ua,
			UserAgentFamily family,
			Instant from,
			Instant to,
			EffectiveUaHeuristicSettings cfg
	) {
		if (jdbcTemplate == null || ua == null || ua.isBlank()) {
			return List.of();
		}
		Set<Long> mitigatedAsns = loadActiveOrRecentMitigatedAsns(from, to);
		String mitIn = buildNumericAsnInClause(mitigatedAsns);
		String mitExpr = mitIn != null
				? "SUM(CASE WHEN asn IN (" + mitIn + ") THEN request_count ELSE 0 END) AS mitigated_asn_requests"
				: "0 AS mitigated_asn_requests";

		String bucketExpr = isPostgres
				? "date_trunc('hour', slot_time)"
				: "strftime('%Y-%m-%d %H:00:00', slot_time / 1000, 'unixepoch')";

		String sql = """
				SELECT
				""" + bucketExpr + """
				 AS hour_bucket,
				    SUM(request_count) AS total_requests,
				    COUNT(*) AS event_count,
				    SUM(CASE WHEN status = 'BLOCKED' THEN request_count ELSE 0 END) AS blocked_requests,
				    SUM(CASE WHEN status = 'MARKED' THEN request_count ELSE 0 END) AS marked_requests,
				    SUM(CASE WHEN status IN ('BLOCKED', 'MARKED') THEN 1 ELSE 0 END) AS incident_events,
				    SUM(CASE WHEN sample_authenticated = TRUE THEN 1 ELSE 0 END) AS auth_samples,
				    SUM(COALESCE(authenticated_count, 0)) AS auth_requests,
				    SUM(CASE WHEN client_type IN ('PRIVATE_NETWORK', 'INTERNAL_NETWORK') THEN request_count ELSE 0 END) AS internal_requests,
				    SUM(CASE WHEN client_type = 'SEARCH_ENGINE' THEN request_count ELSE 0 END) AS search_engine_requests,
				    SUM(CASE WHEN client_type IN ('SEARCH_ENGINE', 'AI_CRAWLER') THEN request_count ELSE 0 END) AS crawler_requests,
				    SUM(CASE WHEN client_type IN ('DATACENTER', 'TOR_EXIT_NODE') THEN request_count ELSE 0 END) AS datacenter_requests,
				    SUM(CASE WHEN client_type IN ('RESIDENTIAL', 'PRIVACY_RELAY') THEN request_count ELSE 0 END) AS residential_requests,
				    SUM(COALESCE(returning_count, 0)) AS returning_requests,
				    SUM(COALESCE(ua_mismatch_count, 0)) AS ua_mismatch_requests,
				    COUNT(DISTINCT NULLIF(subnet_group, '')) AS distinct_subnets,
				    COUNT(DISTINCT asn) AS distinct_asns,
				""" + mitExpr + """
				
				FROM client_events
				WHERE slot_time >= ? AND slot_time <= ?
				  AND TRIM(sample_user_agent) = ?
				GROUP BY hour_bucket
				ORDER BY hour_bucket DESC
				""";

		List<UserAgentHourlyPoint> points = new ArrayList<>();
		try {
			jdbcTemplate.query(sql, rs -> {
				Instant bStart;
				if (isPostgres) {
					Timestamp ts = rs.getTimestamp("hour_bucket");
					bStart = ts != null ? ts.toInstant() : Instant.now();
				} else {
					String bucketStr = rs.getString("hour_bucket");
					bStart = parseSqliteHourString(bucketStr);
				}
				Instant bEnd = bStart.plus(1, ChronoUnit.HOURS);

				long totalReqs = rs.getLong("total_requests");
				int eventCount = rs.getInt("event_count");
				int incEvents = rs.getInt("incident_events");
				int authSamples = rs.getInt("auth_samples");
				long authReqs = rs.getLong("auth_requests");
				long internalReqs = rs.getLong("internal_requests");
				long seReqs = rs.getLong("search_engine_requests");
				long crawlerReqs = rs.getLong("crawler_requests");
				long dcReqs = rs.getLong("datacenter_requests");
				long resReqs = rs.getLong("residential_requests");
				long mmReqs = rs.getLong("ua_mismatch_requests");
				long mitReqs = rs.getLong("mitigated_asn_requests");
				int subnets = rs.getInt("distinct_subnets");
				int asns = rs.getInt("distinct_asns");

				EvaluationOutcome eval = evaluateVerdict(new EvaluationInput(
						ua, family, totalReqs, eventCount, incEvents, 0,
						subnets, asns, authSamples, authReqs, internalReqs, seReqs,
						dcReqs, resReqs, mitReqs, mmReqs, false, null
				), cfg);

				points.add(new UserAgentHourlyPoint(
						bStart, bEnd, totalReqs, eventCount,
						rs.getLong("blocked_requests"), rs.getLong("marked_requests"),
						incEvents, authSamples, authReqs, internalReqs, crawlerReqs,
						dcReqs, resReqs, rs.getLong("returning_requests"), mmReqs,
						subnets, asns,
						eval.verdict(), eval.verdict().pillarCode(), eval.reason()
				));
			}, Timestamp.from(from), Timestamp.from(to), ua);
		} catch (Exception e) {
			log.debug("Failed querying live UA hourly history: {}", e.getMessage());
		}
		return points;
	}

	private static Instant parseSqliteHourString(String str) {
		if (str == null || str.isBlank()) {
			return Instant.now();
		}
		try {
			return Timestamp.valueOf(str.trim()).toInstant();
		} catch (Exception e) {
			return Instant.now();
		}
	}

	private record MitigatedAndSpread24h(
			int distinctSubnets,
			int distinctAsns,
			long mitigatedAsnRequests,
			long searchEngineRequests
	) {}

	private Map<String, MitigatedAndSpread24h> loadExact24hSpreadAndMitigation(
			Instant from,
			Instant to,
			Set<Long> mitigatedAsns
	) {
		if (jdbcTemplate == null) {
			return Map.of();
		}
		String mitIn = buildNumericAsnInClause(mitigatedAsns);
		String mitExpr = mitIn != null
				? "SUM(CASE WHEN asn IN (" + mitIn + ") THEN request_count ELSE 0 END) AS mitigated_asn_requests"
				: "0 AS mitigated_asn_requests";

		String sql = """
				SELECT
				    TRIM(sample_user_agent) AS ua,
				    COUNT(DISTINCT NULLIF(subnet_group, '')) AS distinct_subnets,
				    COUNT(DISTINCT asn) AS distinct_asns,
				    SUM(CASE WHEN client_type = 'SEARCH_ENGINE' THEN request_count ELSE 0 END) AS search_engine_requests,
				""" + mitExpr + """
				
				FROM client_events
				WHERE slot_time >= ? AND slot_time <= ?
				  AND sample_user_agent IS NOT NULL
				  AND TRIM(sample_user_agent) != ''
				GROUP BY TRIM(sample_user_agent)
				""";

		Map<String, MitigatedAndSpread24h> map = new HashMap<>();
		try {
			jdbcTemplate.query(sql, rs -> {
				String ua = rs.getString("ua");
				if (ua != null && !ua.isBlank()) {
					map.put(ua, new MitigatedAndSpread24h(
							rs.getInt("distinct_subnets"),
							rs.getInt("distinct_asns"),
							rs.getLong("mitigated_asn_requests"),
							rs.getLong("search_engine_requests")
					));
				}
			}, Timestamp.from(from), Timestamp.from(to));
		} catch (Exception e) {
			log.debug("Could not query exact 24h spread extras: {}", e.getMessage());
		}
		return map;
	}

	private record ExactSingleUaMetrics(
			long totalRequests,
			int eventCount,
			int distinctSubnets,
			int distinctAsns,
			int authSamples,
			long authRequests,
			long internalRequests,
			long searchEngineRequests,
			long mitigatedAsnRequests
	) {}

	private ExactSingleUaMetrics loadExactSingleUaMetrics(String ua, Instant from, Instant to, Set<Long> mitigatedAsns) {
		if (jdbcTemplate == null || ua == null || ua.isBlank()) {
			return null;
		}
		String mitIn = buildNumericAsnInClause(mitigatedAsns);
		String mitExpr = mitIn != null
				? "SUM(CASE WHEN asn IN (" + mitIn + ") THEN request_count ELSE 0 END) AS mitigated_asn_requests"
				: "0 AS mitigated_asn_requests";

		String sql = """
				SELECT
				    COALESCE(SUM(request_count), 0) AS total_requests,
				    COUNT(*) AS event_count,
				    COUNT(DISTINCT NULLIF(subnet_group, '')) AS distinct_subnets,
				    COUNT(DISTINCT asn) AS distinct_asns,
				    COALESCE(SUM(CASE WHEN sample_authenticated = TRUE THEN 1 ELSE 0 END), 0) AS auth_samples,
				    COALESCE(SUM(authenticated_count), 0) AS auth_requests,
				    COALESCE(SUM(CASE WHEN client_type IN ('PRIVATE_NETWORK', 'INTERNAL_NETWORK') THEN request_count ELSE 0 END), 0) AS internal_requests,
				    COALESCE(SUM(CASE WHEN client_type = 'SEARCH_ENGINE' THEN request_count ELSE 0 END), 0) AS search_engine_requests,
				""" + mitExpr + """
				
				FROM client_events
				WHERE slot_time >= ? AND slot_time <= ?
				  AND TRIM(sample_user_agent) = ?
				""";
		try {
			return jdbcTemplate.query(sql, rs -> {
				if (!rs.next()) return null;
				return new ExactSingleUaMetrics(
						rs.getLong("total_requests"),
						rs.getInt("event_count"),
						rs.getInt("distinct_subnets"),
						rs.getInt("distinct_asns"),
						rs.getInt("auth_samples"),
						rs.getLong("auth_requests"),
						rs.getLong("internal_requests"),
						rs.getLong("search_engine_requests"),
						rs.getLong("mitigated_asn_requests")
				);
			}, Timestamp.from(from), Timestamp.from(to), ua);
		} catch (Exception e) {
			return null;
		}
	}

	public Set<Long> loadActiveOrRecentMitigatedAsns(Instant from, Instant to) {
		if (mitigationRuleRepository == null) {
			return Set.of();
		}
		Set<Long> asns = new HashSet<>();
		try {
			for (MitigationRule r : mitigationRuleRepository.findActiveRules(Instant.now())) {
				if (r.asn() != null && r.asn() > 0) {
					asns.add(r.asn());
				}
			}
			for (MitigationRule r : mitigationRuleRepository.findRulesCreatedBetween(from, to)) {
				if (r.asn() != null && r.asn() > 0) {
					asns.add(r.asn());
				}
			}
		} catch (Exception ignored) {
		}
		return asns;
	}

	private static String buildNumericAsnInClause(Set<Long> asns) {
		if (asns == null || asns.isEmpty()) {
			return null;
		}
		return asns.stream()
				.filter(a -> a != null && a > 0)
				.limit(400)
				.map(String::valueOf)
				.collect(Collectors.joining(","));
	}

	private static double clampPct(double val) {
		return Math.max(0.0, Math.min(100.0, val));
	}

	private static double round1(double val) {
		return Math.round(val * 10.0) / 10.0;
	}

	private static double round2(double val) {
		return Math.round(val * 100.0) / 100.0;
	}
}
