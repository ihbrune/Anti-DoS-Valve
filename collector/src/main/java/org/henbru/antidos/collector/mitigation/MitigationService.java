package org.henbru.antidos.collector.mitigation;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.henbru.antidos.collector.aggregation.UserAgentClassifier;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.enrichment.EntityResolver;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.MitigationUaRule;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.model.NetworkEntity;
import org.henbru.antidos.collector.model.UserAgentAutoVerdict;
import org.henbru.antidos.collector.model.UserAgentFamily;
import org.henbru.antidos.collector.model.UserAgentManualOverride;
import org.henbru.antidos.collector.model.UserAgentProfile;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.notification.AlertNotificationService;
import org.henbru.antidos.collector.poller.ValveStatusClient;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.MitigationUaRuleRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.henbru.antidos.collector.storage.SystemSettingsRepository;
import org.henbru.antidos.collector.storage.UserAgentMemoryRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Orchestrates dynamic CIDR mitigation rules, pre-flight safety guardrails, ASN batch expansion,
 * automatic fleet synchronization to mitigation-capable Valves, and attacker deterrence evaluation.
 */
@Service
public class MitigationService {

	private static final Logger log = LoggerFactory.getLogger(MitigationService.class);

	public static final int MIN_IPV4_PREFIX = 16;
	public static final int MIN_IPV6_PREFIX = 32;
	public static final int CURRENT_HASH_VERSION = 1;
	private static final long DETERRENCE_WINDOW_SECONDS = 600L; // 10 minutes

	public record ValveSyncState(
			long attemptedExpectedRevision,
			long resultingValveRevision,
			int consecutiveMismatches,
			Instant lastSyncAttemptAt,
			Instant backoffUntil,
			String lastReason
	) {
		public boolean isSuppressed(long currentExpectedRevision, Instant now) {
			return attemptedExpectedRevision == currentExpectedRevision
					&& backoffUntil != null
					&& now.isBefore(backoffUntil);
		}
	}

	private final ConcurrentHashMap<String, ValveSyncState> valveSyncStates = new ConcurrentHashMap<>();

	/** Per-thread scope that coalesces multiple fleet sync requests into a single push. */
	private static final class DeferredSyncState {
		int depth;
		boolean pending;
	}

	private final ThreadLocal<DeferredSyncState> deferredFleetSync = new ThreadLocal<>();

	/** Observation phase after activation during which a rule is never considered unused. */
	public static final long OBSERVATION_WINDOW_SECONDS = 600L;

	private final CollectorProperties properties;
	private final MitigationRuleRepository ruleRepository;
	private final MonitoredValveRepository valveRepository;
	private final ValveStatusClient statusClient;
	private final EntityResolver entityResolver;
	private final AlertNotificationService notificationService;
	private final JdbcTemplate jdbcTemplate;
	private final MitigationUaRuleRepository uaRuleRepository;
	private final UserAgentMemoryRepository uaMemoryRepository;
	private final SystemSettingsRepository settingsRepository;

	private final AtomicBoolean deterrenceRefreshPending = new AtomicBoolean(false);
	private final AtomicBoolean deterrenceWorkerRunning = new AtomicBoolean(false);
	private volatile long lastDeterrenceRefreshMillis = 0L;

	@Autowired
	public MitigationService(
			CollectorProperties properties,
			MitigationRuleRepository ruleRepository,
			MonitoredValveRepository valveRepository,
			ValveStatusClient statusClient,
			@Autowired(required = false) EntityResolver entityResolver,
			@Autowired(required = false) AlertNotificationService notificationService,
			JdbcTemplate jdbcTemplate,
			@Autowired(required = false) MitigationUaRuleRepository uaRuleRepository,
			@Autowired(required = false) UserAgentMemoryRepository uaMemoryRepository,
			@Autowired(required = false) SystemSettingsRepository settingsRepository) {
		this.properties = properties;
		this.ruleRepository = ruleRepository;
		this.valveRepository = valveRepository;
		this.statusClient = statusClient;
		this.entityResolver = entityResolver;
		this.notificationService = notificationService;
		this.jdbcTemplate = jdbcTemplate;
		this.uaRuleRepository = uaRuleRepository;
		this.uaMemoryRepository = uaMemoryRepository;
		this.settingsRepository = settingsRepository;
	}

	public MitigationService(
			CollectorProperties properties,
			MitigationRuleRepository ruleRepository,
			MonitoredValveRepository valveRepository,
			ValveStatusClient statusClient,
			EntityResolver entityResolver,
			AlertNotificationService notificationService,
			JdbcTemplate jdbcTemplate) {
		this(properties, ruleRepository, valveRepository, statusClient, entityResolver, notificationService,
				jdbcTemplate, null, null, null);
	}

	public MitigationService(
			CollectorProperties properties,
			MitigationRuleRepository ruleRepository,
			MonitoredValveRepository valveRepository,
			ValveStatusClient statusClient,
			EntityResolver entityResolver,
			JdbcTemplate jdbcTemplate) {
		this(properties, ruleRepository, valveRepository, statusClient, entityResolver, null, jdbcTemplate);
	}

	// =========================================================================
	// DTOs for Pre-Flight Safety Checks, ASN Expansion & Fleet Sync
	// =========================================================================

	public record NormalizedCidr(
			String canonicalCidr,
			int ipVersion,
			int prefixLength
	) {}

	public record PreflightWarning(
			String severity, // "CRITICAL" or "WARNING"
			String cidr,
			String message
	) {
		public String getSeverity() { return severity; }
		public String getCidr() { return cidr; }
		public String getMessage() { return message; }
	}

	public record PreflightCheckResult(
			List<String> validCidrs,
			List<String> invalidInputs,
			List<PreflightWarning> warnings,
			long totalObservedRequests24h,
			long totalAuthenticatedRequests24h,
			boolean safeToProceedWithoutOverride
	) {
		public boolean hasCriticalWarnings() {
			return warnings != null && warnings.stream().anyMatch(w -> "CRITICAL".equalsIgnoreCase(w.severity()));
		}
		public List<String> getValidCidrs() { return validCidrs; }
		public List<String> getInvalidInputs() { return invalidInputs; }
		public List<PreflightWarning> getWarnings() { return warnings; }
		public long getTotalObservedRequests24h() { return totalObservedRequests24h; }
		public long getTotalAuthenticatedRequests24h() { return totalAuthenticatedRequests24h; }
		public boolean isSafeToProceedWithoutOverride() { return safeToProceedWithoutOverride; }
	}

	public record AsnSubnetCandidate(
			String subnetCidr,
			long totalRequests,
			long blockedRequests,
			int distinctIps,
			boolean alreadyBlocked,
			boolean anonOnlyScope
	) {
		public AsnSubnetCandidate(
				String subnetCidr,
				long totalRequests,
				long blockedRequests,
				int distinctIps,
				boolean alreadyBlocked
		) {
			this(subnetCidr, totalRequests, blockedRequests, distinctIps, alreadyBlocked, false);
		}

		public String getSubnetCidr() { return subnetCidr; }
		public long getTotalRequests() { return totalRequests; }
		public long getBlockedRequests() { return blockedRequests; }
		public int getDistinctIps() { return distinctIps; }
		public boolean isAlreadyBlocked() { return alreadyBlocked; }
		public boolean isAnonOnlyScope() { return anonOnlyScope; }
	}

	public record AsnBatchPreview(
			long asn,
			String asnOrganization,
			int hours,
			List<AsnSubnetCandidate> candidates,
			int skippedAuthenticatedSubnets,
			long totalCandidateRequests
	) {
		public long getAsn() { return asn; }
		public String getAsnOrganization() { return asnOrganization; }
		public int getHours() { return hours; }
		public List<AsnSubnetCandidate> getCandidates() { return candidates; }
		public int getSkippedAuthenticatedSubnets() { return skippedAuthenticatedSubnets; }
		public long getTotalCandidateRequests() { return totalCandidateRequests; }
	}

	public record FleetSyncResult(
			int targetValvesCount,
			int syncedValvesCount,
			int activeRulesCount,
			long revision,
			List<String> errors
	) {}

	// =========================================================================
	// Canonical CIDR Normalization & Revision Hashing (Matches Valve 1:1)
	// =========================================================================

	/**
	 * Parses, validates, and normalizes an IPv4 or IPv6 address or CIDR string.
	 * Rejects overly broad prefixes ({@code < /16} for IPv4, {@code < /32} for IPv6 by default).
	 */
	public static NormalizedCidr normalizeAndValidateCidr(String rawInput) {
		return normalizeAndValidateCidr(rawInput, MIN_IPV4_PREFIX, MIN_IPV6_PREFIX);
	}

	/**
	 * Parses, validates, and normalizes an IPv4 or IPv6 address or CIDR string against dynamic prefix guardrails.
	 *
	 * @param rawInput      Raw CIDR or IP address string
	 * @param minIpv4Prefix Broadest allowed IPv4 prefix (1..32)
	 * @param minIpv6Prefix Broadest allowed IPv6 prefix (1..128)
	 * @return Canonical {@link NormalizedCidr}
	 * @throws IllegalArgumentException If syntax is invalid or prefix is broader than the minimum
	 */
	public static NormalizedCidr normalizeAndValidateCidr(String rawInput, int minIpv4Prefix, int minIpv6Prefix) {
		if (rawInput == null || rawInput.trim().isEmpty()) {
			throw new IllegalArgumentException("CIDR or IP address must not be empty.");
		}
		int safeMinV4 = Math.max(1, Math.min(32, minIpv4Prefix));
		int safeMinV6 = Math.max(1, Math.min(128, minIpv6Prefix));
		String s = rawInput.trim();
		int slashIdx = s.indexOf('/');
		String ipPart = slashIdx >= 0 ? s.substring(0, slashIdx).trim() : s;
		String prefixPart = slashIdx >= 0 ? s.substring(slashIdx + 1).trim() : null;

		if (ipPart.indexOf(':') < 0) {
			byte[] ipv4 = parseIPv4Literal(ipPart);
			if (ipv4 == null) {
				throw new IllegalArgumentException("Invalid IPv4 address in CIDR: '" + rawInput + "'");
			}
			int prefix = 32;
			if (prefixPart != null) {
				try {
					prefix = Integer.parseInt(prefixPart);
				} catch (NumberFormatException e) {
					throw new IllegalArgumentException("Invalid IPv4 prefix length in CIDR: '" + rawInput + "'");
				}
			}
			if (prefix < safeMinV4 || prefix > 32) {
				throw new IllegalArgumentException(
						"IPv4 prefix length must be between /" + safeMinV4 + " and /32 (got /" + prefix + " in '" + rawInput + "').");
			}
			int addr = ((ipv4[0] & 0xFF) << 24)
					| ((ipv4[1] & 0xFF) << 16)
					| ((ipv4[2] & 0xFF) << 8)
					| (ipv4[3] & 0xFF);
			int mask = prefix >= 32 ? 0xFFFFFFFF : (int) (0xFFFFFFFF00000000L >>> prefix);
			int masked = addr & mask;
			String canonical = ((masked >>> 24) & 0xFF) + "."
					+ ((masked >>> 16) & 0xFF) + "."
					+ ((masked >>> 8) & 0xFF) + "."
					+ (masked & 0xFF) + "/" + prefix;
			return new NormalizedCidr(canonical, 4, prefix);
		} else {
			if (ipPart.startsWith("[") && ipPart.endsWith("]")) {
				ipPart = ipPart.substring(1, ipPart.length() - 1);
			}
			byte[] ipv6;
			try {
				InetAddress addr = InetAddress.getByName(ipPart);
				if (!(addr instanceof Inet6Address)) {
					throw new IllegalArgumentException("Invalid IPv6 address in CIDR: '" + rawInput + "'");
				}
				ipv6 = addr.getAddress();
			} catch (UnknownHostException e) {
				throw new IllegalArgumentException("Invalid IPv6 address in CIDR: '" + rawInput + "'");
			}
			int prefix = 128;
			if (prefixPart != null) {
				try {
					prefix = Integer.parseInt(prefixPart);
				} catch (NumberFormatException e) {
					throw new IllegalArgumentException("Invalid IPv6 prefix length in CIDR: '" + rawInput + "'");
				}
			}
			if (prefix < safeMinV6 || prefix > 128) {
				throw new IllegalArgumentException(
						"IPv6 prefix length must be between /" + safeMinV6 + " and /128 (got /" + prefix + " in '" + rawInput + "').");
			}
			long hi = bytesToLong(ipv6, 0);
			long lo = bytesToLong(ipv6, 8);
			if (prefix == 64) {
				lo = 0L;
			} else if (prefix < 64) {
				long maskHi = ~0L << (64 - prefix);
				hi &= maskHi;
				lo = 0L;
			} else if (prefix < 128) {
				long maskLo = ~0L << (128 - prefix);
				lo &= maskLo;
			}
			byte[] maskedBytes = new byte[16];
			longToBytes(hi, maskedBytes, 0);
			longToBytes(lo, maskedBytes, 8);
			try {
				String canonicalIp = InetAddress.getByAddress(maskedBytes).getHostAddress();
				return new NormalizedCidr(canonicalIp + "/" + prefix, 6, prefix);
			} catch (UnknownHostException e) {
				throw new IllegalArgumentException("Invalid IPv6 address in CIDR: '" + rawInput + "'");
			}
		}
	}

	/**
	 * Computes the exact same 53-bit positive FNV-1a revision hash over sorted canonical CIDRs
	 * as {@code AntiDoSDynamicBlockRegistry.computeRevisionForCidrs}.
	 */
	public static long computeRevisionForCidrs(Collection<String> cidrs) {
		if (cidrs == null || cidrs.isEmpty()) {
			return 0L;
		}
		List<String> sorted = new ArrayList<>(cidrs);
		Collections.sort(sorted);
		long hash = 0xcbf29ce484222325L;
		for (String cidr : sorted) {
			if (cidr == null) {
				continue;
			}
			for (int i = 0; i < cidr.length(); i++) {
				hash ^= cidr.charAt(i);
				hash *= 0x100000001b3L;
			}
			hash ^= '\n';
			hash *= 0x100000001b3L;
		}
		long rev = hash & 0x1FFFFFFFFFFFFFL;
		return rev == 0L ? 1L : rev;
	}

	public static final Duration MIN_SYNC_REMAINING_TTL = Duration.ofSeconds(5);

	public List<MitigationRule> getActiveRulesForSync(Instant now) {
		if (!properties.isViewerMode()) {
			ruleRepository.expireElapsedRules(now);
		}
		return ruleRepository.findActiveRules(now.plus(MIN_SYNC_REMAINING_TTL));
	}

	public long getExpectedRevision(Instant now) {
		List<MitigationRule> active = getActiveRulesForSync(now);
		if (active.isEmpty()) {
			return 0L;
		}
		List<String> cidrs = active.stream().map(MitigationRule::cidr).toList();
		return computeRevisionForCidrs(cidrs);
	}

	/**
	 * Computes the exact same 53-bit positive FNV-1a revision hash over sorted decimal 32-bit UA hashes
	 * as {@code AntiDoSDynamicBlockRegistry.computeRevisionForUaHashes}.
	 */
	public static long computeRevisionForUaHashes(Collection<Integer> uaHashes) {
		if (uaHashes == null || uaHashes.isEmpty()) {
			return 0L;
		}
		List<String> sorted = new ArrayList<>(uaHashes.size());
		for (Integer h : uaHashes) {
			if (h != null) {
				sorted.add(Integer.toString(h));
			}
		}
		return computeRevisionForCidrs(sorted);
	}

	public List<MitigationUaRule> getActiveUaRulesForSync(Instant now) {
		if (uaRuleRepository == null) {
			return List.of();
		}
		if (!properties.isViewerMode()) {
			uaRuleRepository.expireElapsedRules(now);
		}
		return uaRuleRepository.findActiveRules(now.plus(MIN_SYNC_REMAINING_TTL));
	}

	public long getExpectedUaRevision(Instant now) {
		List<MitigationUaRule> active = getActiveUaRulesForSync(now);
		if (active.isEmpty()) {
			return 0L;
		}
		return computeRevisionForUaHashes(active.stream().map(MitigationUaRule::uaHash32).toList());
	}

	public List<MitigationUaRule> getActiveUaRules() {
		if (uaRuleRepository == null) {
			return List.of();
		}
		Instant now = Instant.now();
		if (!properties.isViewerMode()) {
			uaRuleRepository.expireElapsedRules(now);
		}
		return uaRuleRepository.findActiveRules(now);
	}

	// =========================================================================
	// Fleet Guardrails & Policy Helpers
	// =========================================================================

	/**
	 * @return The strictest (largest prefix number) minimal IPv4 prefix configured across active mitigation Valves
	 */
	public int getEffectiveMinIpv4Prefix() {
		return computeMinIpv4Prefix(getMitigationCapableValves());
	}

	private int computeMinIpv4Prefix(List<MonitoredValve> valves) {
		int max = MIN_IPV4_PREFIX;
		for (MonitoredValve v : valves) {
			if (v.mitigationMinPrefixV4() > max) {
				max = v.mitigationMinPrefixV4();
			}
		}
		return max;
	}

	/**
	 * @return The strictest (largest prefix number) minimal IPv6 prefix configured across active mitigation Valves
	 */
	public int getEffectiveMinIpv6Prefix() {
		return computeMinIpv6Prefix(getMitigationCapableValves());
	}

	private int computeMinIpv6Prefix(List<MonitoredValve> valves) {
		int max = MIN_IPV6_PREFIX;
		for (MonitoredValve v : valves) {
			if (v.mitigationMinPrefixV6() > max) {
				max = v.mitigationMinPrefixV6();
			}
		}
		return max;
	}

	/**
	 * @return The strictest (lowest duration in seconds) maximum TTL configured across active mitigation Valves
	 */
	public int getEffectiveMaxTtlSeconds() {
		return computeMaxTtlSeconds(getMitigationCapableValves());
	}

	private int computeMaxTtlSeconds(List<MonitoredValve> valves) {
		int min = 86400;
		for (MonitoredValve v : valves) {
			if (v.mitigationMaxTtlSeconds() > 0 && v.mitigationMaxTtlSeconds() < min) {
				min = v.mitigationMaxTtlSeconds();
			}
		}
		return min;
	}

	/**
	 * @return The strictest (lowest maximum count) active blocks capacity limit across active mitigation Valves
	 */
	public int getEffectiveMaxActiveBlocks() {
		return computeMaxActiveBlocks(getMitigationCapableValves());
	}

	private int computeMaxActiveBlocks(List<MonitoredValve> valves) {
		int min = 5000;
		for (MonitoredValve v : valves) {
			if (v.mitigationMaxActiveBlocks() > 0 && v.mitigationMaxActiveBlocks() < min) {
				min = v.mitigationMaxActiveBlocks();
			}
		}
		return min;
	}

	// =========================================================================
	// Pre-Flight Safety Check
	// =========================================================================

	public PreflightCheckResult evaluatePreflight(Collection<String> rawInputs) {
		if (rawInputs == null || rawInputs.isEmpty()) {
			return new PreflightCheckResult(List.of(), List.of("No CIDR or IP specified."), List.of(), 0L, 0L, false);
		}

		List<MonitoredValve> mitigationValves = getMitigationCapableValves();
		int minV4 = computeMinIpv4Prefix(mitigationValves);
		int minV6 = computeMinIpv6Prefix(mitigationValves);

		List<String> validCidrs = new ArrayList<>();
		List<String> invalidInputs = new ArrayList<>();
		List<PreflightWarning> warnings = new ArrayList<>();
		long totalObsReq = 0L;
		long totalAuthReq = 0L;

		Instant cutoff24h = Instant.now().minus(Duration.ofHours(24));

		for (String raw : rawInputs) {
			if (raw == null || raw.isBlank()) {
				continue;
			}
			NormalizedCidr norm;
			try {
				norm = normalizeAndValidateCidr(raw, minV4, minV6);
			} catch (IllegalArgumentException e) {
				invalidInputs.add(e.getMessage());
				continue;
			}
			if (!validCidrs.contains(norm.canonicalCidr())) {
				validCidrs.add(norm.canonicalCidr());
			}

			String privateDesc = IpNetworkUtil.getPrivateNetworkDescription(norm.canonicalCidr());
			if (privateDesc != null) {
				warnings.add(new PreflightWarning(
						"CRITICAL",
						norm.canonicalCidr(),
						"Internal / Private Network range detected (" + privateDesc + "). Blocking may lock out internal services or admins."));
			}

			// Check 24h rollup telemetry for authenticated users or search engines in this subnet
			String subnetGroup = IpNetworkUtil.parse(norm.canonicalCidr()).subnetGroup();
			try {
				Map<String, Object> row = jdbcTemplate.queryForMap("""
						SELECT COALESCE(SUM(total_requests), 0) AS tot_req,
						       COALESCE(SUM(authenticated_requests), 0) AS auth_req,
						       MAX(CASE WHEN client_type = 'SEARCH_ENGINE' THEN 1 ELSE 0 END) AS is_se
						FROM client_subnet_rollups
						WHERE (subnet_group = ? OR subnet_group = ?)
						  AND bucket_start >= ?
						""",
						norm.canonicalCidr(), subnetGroup, Timestamp.from(cutoff24h));

				long reqs = ((Number) row.get("tot_req")).longValue();
				long auths = ((Number) row.get("auth_req")).longValue();
				int isSe = ((Number) row.get("is_se")).intValue();
				totalObsReq += reqs;
				totalAuthReq += auths;

				if (auths > 0) {
					warnings.add(new PreflightWarning(
							"CRITICAL",
							norm.canonicalCidr(),
							"Collateral Damage Risk: " + auths + " authenticated user request(s) observed from this subnet in the last 24h."));
				} else if (reqs > 0 && valveRepository != null) {
					try {
						List<Map<String, Object>> reportingValves = jdbcTemplate.queryForList("""
								SELECT DISTINCT server_id, valve_name
								FROM client_subnet_rollups
								WHERE (subnet_group = ? OR subnet_group = ?)
								  AND bucket_start >= ?
								""", norm.canonicalCidr(), subnetGroup, Timestamp.from(cutoff24h));
						if (!reportingValves.isEmpty()) {
							boolean allAnonOnly = true;
							for (Map<String, Object> rv : reportingValves) {
								String sid = (String) rv.get("server_id");
								String vn = (String) rv.get("valve_name");
								var mvOpt = valveRepository.findByServerIdAndValveName(sid, vn);
								if (mvOpt.isEmpty() || !mvOpt.get().isUnauthenticatedOnly()) {
									allAnonOnly = false;
									break;
								}
							}
							if (allAnonOnly) {
								warnings.add(new PreflightWarning(
										"WARNING",
										norm.canonicalCidr(),
										"Auth Scope Notice: Observed 24h traffic (" + reqs + " reqs) originated exclusively from valve(s) with 'relevantAuthScope=UNAUTHENTICATED_ONLY'. Authenticated users bypass these valves, so 0 recorded authenticated requests cannot rule out collateral damage on active user sessions."));
							}
						}
					} catch (Exception e) {
						log.debug("Auth scope check skipped for {}: {}", norm.canonicalCidr(), e.getMessage());
					}
				}
				if (isSe > 0) {
					warnings.add(new PreflightWarning(
							"CRITICAL",
							norm.canonicalCidr(),
							"Verified Search Engine crawler traffic observed in this subnet in the last 24h."));
				}
			} catch (Exception e) {
				log.debug("Preflight rollup check skipped for {}: {}", norm.canonicalCidr(), e.getMessage());
			}
		}

		// Capacity check against fleet guardrails
		if (!validCidrs.isEmpty()) {
			int maxCap = computeMaxActiveBlocks(mitigationValves);
			List<MitigationRule> active = ruleRepository.findActiveRules(Instant.now());
			Set<String> activeCidrs = new HashSet<>(active.stream().map(MitigationRule::cidr).toList());
			long newCount = validCidrs.stream().filter(c -> !activeCidrs.contains(c)).count();
			if (active.size() + newCount > maxCap) {
				warnings.add(new PreflightWarning(
						"CRITICAL",
						"FLEET_CAPACITY",
						"Fleet capacity limit exceeded: adding " + newCount + " new rule(s) would result in "
								+ (active.size() + newCount) + " active rules, exceeding fleet limit of " + maxCap + "."));
			}
		}

		boolean safe = invalidInputs.isEmpty()
				&& !validCidrs.isEmpty()
				&& warnings.stream().noneMatch(w -> "CRITICAL".equalsIgnoreCase(w.severity()));

		return new PreflightCheckResult(validCidrs, invalidInputs, warnings, totalObsReq, totalAuthReq, safe);
	}

	// =========================================================================
	// Rule Creation, Extension, Revocation & ASN Batch Operations
	// =========================================================================

	public MitigationRule createOrUpdateBlock(
			String rawCidr,
			int ttlMinutes,
			String reason,
			String source,
			String batchId,
			String actor) {
		requireWriteMode("Creating or updating mitigation blocks");
		List<MonitoredValve> valves = getMitigationCapableValves();
		return createOrUpdateBlockInternal(rawCidr, ttlMinutes, reason, source, batchId, actor,
				computeMinIpv4Prefix(valves), computeMinIpv6Prefix(valves), computeMaxTtlSeconds(valves));
	}

	private MitigationRule createOrUpdateBlockInternal(
			String rawCidr,
			int ttlMinutes,
			String reason,
			String source,
			String batchId,
			String actor,
			int minV4,
			int minV6,
			int maxTtlSec) {
		NormalizedCidr norm = normalizeAndValidateCidr(rawCidr, minV4, minV6);
		int effectiveTtlMin = ttlMinutes > 0 ? ttlMinutes : properties.getDefaultMitigationTtlMinutes();
		if ((long) effectiveTtlMin * 60L > maxTtlSec) {
			int cappedMin = Math.max(1, maxTtlSec / 60);
			log.info("Capping requested dynamic block TTL from {} min to fleet max {} min ({} s) for {}",
					effectiveTtlMin, cappedMin, maxTtlSec, norm.canonicalCidr());
			effectiveTtlMin = cappedMin;
		}
		Instant now = Instant.now();
		Instant expiresAt = now.plus(Duration.ofMinutes(effectiveTtlMin));

		Long asn = null;
		String asnOrg = null;
		Optional<MitigationRule> existingOpt = ruleRepository.findByCidrAndScope(norm.canonicalCidr(), "ALL");

		// Enrich ASN metadata from rollups or EntityResolver
		try {
			List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
					SELECT asn, as_org FROM client_subnet_rollups
					WHERE subnet_group = ? AND asn IS NOT NULL AND asn > 0
					ORDER BY bucket_start DESC LIMIT 1
					""", norm.canonicalCidr());
			if (!rows.isEmpty()) {
				Object asnObj = rows.getFirst().get("asn");
				if (asnObj instanceof Number n) {
					asn = n.longValue();
				}
				asnOrg = (String) rows.getFirst().get("as_org");
			} else if (entityResolver != null) {
				Optional<NetworkEntity> cached = entityResolver.getCached(norm.canonicalCidr());
				if (cached.isPresent() && cached.get().asn() != null) {
					asn = cached.get().asn();
					asnOrg = cached.get().asOrg();
				}
			}
		} catch (Exception ignored) {
		}

		String safeReason = (reason != null && !reason.isBlank()) ? reason.trim() : "Manual dynamic CIDR mitigation";
		String safeSource = (source != null && !source.isBlank()) ? source.trim() : MitigationRule.SOURCE_MANUAL;

		// A rule row is reused when the same CIDR is blocked again. If the previous incarnation is no longer
		// active, start a fresh lifecycle: reset activation time and hit statistics so that deterrence tracking,
		// the max-extension cap and unused-rule eviction are not skewed by stale history.
		boolean continuesActiveRule = existingOpt.isPresent() && existingOpt.get().isCurrentlyActive(now);
		Optional<MitigationRule> carried = continuesActiveRule ? existingOpt : Optional.empty();

		MitigationRule rule = new MitigationRule(
				existingOpt.map(MitigationRule::id).orElse(null),
				norm.canonicalCidr(),
				norm.ipVersion(),
				norm.prefixLength(),
				"ALL",
				MitigationRule.STATUS_ACTIVE,
				safeSource,
				batchId,
				safeReason,
				asn != null ? asn : existingOpt.map(MitigationRule::asn).orElse(null),
				asnOrg != null ? asnOrg : existingOpt.map(MitigationRule::asnOrganization).orElse(null),
				carried.map(MitigationRule::createdAt).orElse(now),
				now,
				expiresAt,
				null,
				null,
				carried.map(MitigationRule::totalBlockedHits).orElse(0L),
				carried.map(MitigationRule::peakDistinctIps).orElse(0),
				carried.map(MitigationRule::lastHitAt).orElse(null),
				MitigationRule.DETERRENCE_OBSERVING
		);

		MitigationRule saved = ruleRepository.upsertRule(rule);
		if (batchId == null) {
			ruleRepository.insertAuditEntry(new MitigationAuditEntry(
					null,
					saved.id(),
					saved.cidr(),
					null,
					existingOpt.isPresent() && existingOpt.get().isCurrentlyActive(now) ? "EXTEND" : "CREATE",
					actor != null ? actor : "ADMIN",
					effectiveTtlMin * 60,
					safeReason,
					now
			));
			syncFleetMitigations();
		}
		return saved;
	}

	public List<MitigationRule> createBatchBlocks(
			Collection<String> rawCidrs,
			int ttlMinutes,
			String reason,
			String source,
			String batchIdPrefix,
			String actor) {
		requireWriteMode("Creating batch mitigation blocks");
		if (rawCidrs == null || rawCidrs.isEmpty()) {
			return List.of();
		}
		List<MonitoredValve> valves = getMitigationCapableValves();
		int minV4 = computeMinIpv4Prefix(valves);
		int minV6 = computeMinIpv6Prefix(valves);
		int maxTtlSec = computeMaxTtlSeconds(valves);
		String batchId = (batchIdPrefix != null && !batchIdPrefix.isBlank() ? batchIdPrefix : "BATCH")
				+ "-" + (System.currentTimeMillis() / 1000L);
		int effectiveTtlMin = ttlMinutes > 0 ? ttlMinutes : properties.getDefaultMitigationTtlMinutes();
		List<MitigationRule> created = new ArrayList<>();
		for (String raw : rawCidrs) {
			if (raw == null || raw.isBlank()) {
				continue;
			}
			MitigationRule r = createOrUpdateBlockInternal(raw, effectiveTtlMin, reason, source, batchId, actor,
					minV4, minV6, maxTtlSec);
			created.add(r);
		}
		if (!created.isEmpty()) {
			ruleRepository.insertAuditEntry(new MitigationAuditEntry(
					null,
					created.getFirst().id(),
					created.size() + " subnets (" + created.getFirst().cidr() + "...)",
					batchId,
					"AUTO_ENGINE".equals(actor) ? "AUTO_BLOCK" : "BATCH_CREATE",
					actor != null ? actor : "ADMIN",
					effectiveTtlMin * 60,
					(reason != null ? reason : "Batch mitigation") + " [" + created.size() + " rules]",
					Instant.now()
			));
			syncFleetMitigations();
		}
		return created;
	}

	/**
	 * Queries {@code client_subnet_rollups} to preview all active unauthenticated subnets for a given ASN.
	 */
	public AsnBatchPreview previewAsnBatch(long asn, int hours) {
		int safeHours = Math.max(1, Math.min(hours, 720));
		Instant cutoff = Instant.now().minus(Duration.ofHours(safeHours));
		Set<String> currentlyBlocked = new LinkedHashSet<>(
				ruleRepository.findActiveRules(Instant.now()).stream().map(MitigationRule::cidr).toList());

		List<AsnSubnetCandidate> candidates = new ArrayList<>();
		int[] skippedAuth = {0};
		String[] asnOrgHolder = {"ASN " + asn};
		long[] totalCandidateReqs = {0L};

		jdbcTemplate.query("""
				SELECT subnet_group,
				       MAX(COALESCE(as_org, 'ASN ' || CAST(asn AS TEXT))) AS as_org,
				       SUM(total_requests) AS tot_req,
				       SUM(blocked_requests) AS blk_req,
				       MAX(distinct_clients) AS max_ips,
				       SUM(authenticated_requests) AS auth_req
				FROM client_subnet_rollups
				WHERE asn = ?
				  AND bucket_start >= ?
				  AND (client_type IS NULL OR client_type NOT IN ('SEARCH_ENGINE', 'AI_CRAWLER', 'PRIVATE_NETWORK', 'INTERNAL_NETWORK'))
				GROUP BY subnet_group
				ORDER BY tot_req DESC
				""", rs -> {
			String subnet = rs.getString("subnet_group");
			String org = rs.getString("as_org");
			if (org != null && !org.isBlank()) {
				asnOrgHolder[0] = org;
			}
			long totReq = rs.getLong("tot_req");
			long blkReq = rs.getLong("blk_req");
			int maxIps = rs.getInt("max_ips");
			long authReq = rs.getLong("auth_req");

			if (authReq > 0) {
				skippedAuth[0]++;
				return;
			}
			boolean isAnonOnly = false;
			if (valveRepository != null) {
				try {
					List<Map<String, Object>> reportingValves = jdbcTemplate.queryForList("""
							SELECT DISTINCT server_id, valve_name
							FROM client_subnet_rollups
							WHERE subnet_group = ? AND bucket_start >= ?
							""", subnet, Timestamp.from(cutoff));
					if (!reportingValves.isEmpty()) {
						boolean allAnon = true;
						for (Map<String, Object> rv : reportingValves) {
							String sid = (String) rv.get("server_id");
							String vn = (String) rv.get("valve_name");
							var mvOpt = valveRepository.findByServerIdAndValveName(sid, vn);
							if (mvOpt.isEmpty() || !mvOpt.get().isUnauthenticatedOnly()) {
								allAnon = false;
								break;
							}
						}
						isAnonOnly = allAnon;
					}
				} catch (Exception e) {
					log.debug("ASN preview auth scope check skipped for {}: {}", subnet, e.getMessage());
				}
			}
			try {
				NormalizedCidr norm = normalizeAndValidateCidr(subnet);
				candidates.add(new AsnSubnetCandidate(
						norm.canonicalCidr(),
						totReq,
						blkReq,
						maxIps,
						currentlyBlocked.contains(norm.canonicalCidr()),
						isAnonOnly
				));
				totalCandidateReqs[0] += totReq;
			} catch (IllegalArgumentException ignored) {
			}
		}, asn, Timestamp.from(cutoff));

		return new AsnBatchPreview(
				asn,
				asnOrgHolder[0],
				safeHours,
				candidates,
				skippedAuth[0],
				totalCandidateReqs[0]
		);
	}

	/**
	 * Expands an attacking ASN into all active unauthenticated subnets from the last {@code hours}
	 * and blocks them as a single batch.
	 */
	public List<MitigationRule> blockAsnSubnets(long asn, int hours, int ttlMinutes, String reason, String actor) {
		requireWriteMode("Blocking ASN subnets");
		AsnBatchPreview preview = previewAsnBatch(asn, hours);
		if (preview.candidates().isEmpty()) {
			return List.of();
		}
		List<String> cidrs = preview.candidates().stream().map(AsnSubnetCandidate::subnetCidr).toList();
		String effectiveReason = (reason != null && !reason.isBlank())
				? reason.trim()
				: "ASN " + asn + " (" + preview.asnOrganization() + ") Batch Mitigation";
		return createBatchBlocks(cidrs, ttlMinutes, effectiveReason, MitigationRule.SOURCE_ASN_BATCH, "ASN-" + asn, actor);
	}

	public Optional<MitigationRule> extendBlock(long ruleId, int additionalMinutes, String actor) {
		requireWriteMode("Extending mitigation blocks");
		Optional<MitigationRule> opt = ruleRepository.findById(ruleId);
		if (opt.isEmpty()) {
			return Optional.empty();
		}
		MitigationRule existing = opt.get();
		int addMin = additionalMinutes > 0 ? additionalMinutes : properties.getDefaultMitigationTtlMinutes();
		Instant now = Instant.now();
		Instant base = (existing.expiresAt() != null && existing.expiresAt().isAfter(now) && MitigationRule.STATUS_ACTIVE.equals(existing.status()))
				? existing.expiresAt()
				: now;
		Instant newExpiresAt = base.plus(Duration.ofMinutes(addMin));

		MitigationRule updated = new MitigationRule(
				existing.id(),
				existing.cidr(),
				existing.ipVersion(),
				existing.prefixLength(),
				existing.targetScope(),
				MitigationRule.STATUS_ACTIVE,
				existing.source(),
				existing.batchId(),
				existing.reason(),
				existing.asn(),
				existing.asnOrganization(),
				existing.createdAt(),
				now,
				newExpiresAt,
				null,
				null,
				existing.totalBlockedHits(),
				existing.peakDistinctIps(),
				existing.lastHitAt(),
				existing.deterrenceState()
		);
		MitigationRule saved = ruleRepository.upsertRule(updated);
		ruleRepository.insertAuditEntry(new MitigationAuditEntry(
				null,
				saved.id(),
				saved.cidr(),
				saved.batchId(),
				"EXTEND",
				actor != null ? actor : "ADMIN",
				(int) Duration.between(now, newExpiresAt).toSeconds(),
				"Extended by +" + addMin + " min",
				now
		));
		syncFleetMitigations();
		return Optional.of(saved);
	}

	public Optional<MitigationRule> revokeBlock(long ruleId, String revokeReason, String actor) {
		requireWriteMode("Revoking mitigation blocks");
		Optional<MitigationRule> opt = ruleRepository.findById(ruleId);
		if (opt.isEmpty()) {
			return Optional.empty();
		}
		MitigationRule existing = opt.get();
		Instant now = Instant.now();
		String safeRevokeReason = (revokeReason != null && !revokeReason.isBlank()) ? revokeReason.trim() : "Manually revoked by operator";

		MitigationRule updated = new MitigationRule(
				existing.id(),
				existing.cidr(),
				existing.ipVersion(),
				existing.prefixLength(),
				existing.targetScope(),
				MitigationRule.STATUS_REVOKED,
				existing.source(),
				existing.batchId(),
				existing.reason(),
				existing.asn(),
				existing.asnOrganization(),
				existing.createdAt(),
				now,
				now,
				now,
				safeRevokeReason,
				existing.totalBlockedHits(),
				existing.peakDistinctIps(),
				existing.lastHitAt(),
				existing.deterrenceState()
		);
		MitigationRule saved = ruleRepository.upsertRule(updated);
		ruleRepository.insertAuditEntry(new MitigationAuditEntry(
				null,
				saved.id(),
				saved.cidr(),
				saved.batchId(),
				"REVOKE",
				actor != null ? actor : "ADMIN",
				0,
				safeRevokeReason,
				now
		));
		syncFleetMitigations();
		return Optional.of(saved);
	}

	public int revokeBatch(String batchId, String revokeReason, String actor) {
		requireWriteMode("Revoking mitigation batches");
		if (batchId == null || batchId.isBlank()) {
			return 0;
		}
		List<MitigationRule> rules = ruleRepository.findByBatchId(batchId.trim());
		if (rules.isEmpty()) {
			return 0;
		}
		Instant now = Instant.now();
		String safeRevokeReason = (revokeReason != null && !revokeReason.isBlank())
				? revokeReason.trim()
				: "Batch " + batchId + " revoked by operator";
		int count = 0;
		for (MitigationRule existing : rules) {
			if (!MitigationRule.STATUS_ACTIVE.equals(existing.status())) {
				continue;
			}
			MitigationRule updated = new MitigationRule(
					existing.id(),
					existing.cidr(),
					existing.ipVersion(),
					existing.prefixLength(),
					existing.targetScope(),
					MitigationRule.STATUS_REVOKED,
					existing.source(),
					existing.batchId(),
					existing.reason(),
					existing.asn(),
					existing.asnOrganization(),
					existing.createdAt(),
					now,
					now,
					now,
					safeRevokeReason,
					existing.totalBlockedHits(),
					existing.peakDistinctIps(),
					existing.lastHitAt(),
					existing.deterrenceState()
			);
			ruleRepository.upsertRule(updated);
			count++;
		}
		if (count > 0) {
			ruleRepository.insertAuditEntry(new MitigationAuditEntry(
					null,
					rules.getFirst().id(),
					count + " rules in batch " + batchId,
					batchId,
					"BATCH_REVOKE",
					actor != null ? actor : "ADMIN",
					0,
					safeRevokeReason,
					now
			));
			syncFleetMitigations();
		}
		return count;
	}

	/**
	 * Emergency flush: revokes ALL active dynamic mitigation rules immediately and synchronizes
	 * an empty rule set to all mitigation-capable Valves across the fleet.
	 *
	 * @param revokeReason Optional reason for the emergency flush
	 * @param actor        Operator identity executing the emergency flush
	 * @return Number of revoked active rules
	 */
	public int revokeAll(String revokeReason, String actor) {
		requireWriteMode("Emergency flush");
		Instant now = Instant.now();
		String safeRevokeReason = (revokeReason != null && !revokeReason.isBlank())
				? revokeReason.trim()
				: "Emergency flush executed by operator";
		int count = ruleRepository.revokeAllActive(now, safeRevokeReason);
		ruleRepository.insertAuditEntry(new MitigationAuditEntry(
				null,
				null,
				"ALL",
				null,
				"EMERGENCY_FLUSH",
				actor != null ? actor : "ADMIN",
				0,
				safeRevokeReason + " (" + count + " active rule(s) revoked)",
				now
		));
		syncFleetMitigations();
		if (notificationService != null) {
			notificationService.sendEmergencyFlushAlert(count, safeRevokeReason, actor);
		}
		return count;
	}

	// =========================================================================
	// Fleet Synchronization & Auto-Discovery
	// =========================================================================

	/**
	 * Pushes the full active rule set ({@code action=replace}) to all active monitored Valves
	 * that have {@code dynamicMitigationEnabled = true}.
	 */
	public FleetSyncResult syncFleetMitigations() {
		requireWriteMode("Fleet mitigation synchronization");
		DeferredSyncState deferred = deferredFleetSync.get();
		if (deferred != null && deferred.depth > 0) {
			// Coalesce: the outermost deferred scope performs a single sync with the final rule set.
			deferred.pending = true;
			return new FleetSyncResult(0, 0, 0, 0L, List.of());
		}
		Instant now = Instant.now();
		List<MitigationRule> activeRules = getActiveRulesForSync(now);
		String blocksPayload = buildBlocksPayload(activeRules);
		long expectedRevision = computeRevisionForCidrs(activeRules.stream().map(MitigationRule::cidr).toList());

		List<MitigationUaRule> activeUaRules = getActiveUaRulesForSync(now);
		String uaBlocksPayload = buildUaBlocksPayload(activeUaRules);
		long expectedUaRevision = computeRevisionForUaHashes(activeUaRules.stream().map(MitigationUaRule::uaHash32).toList());

		List<MonitoredValve> mitigationValves = valveRepository.findAllActive().stream()
				.filter(MonitoredValve::dynamicMitigationEnabled)
				.toList();

		if (properties.getMode().isOperator()) {
			log.info("Operator mode: persisted {} active CIDR rule(s) (rev {}) and {} active UA rule(s) (rev {}); active Valve push delegated to HEADLESS/FULL collector.",
					activeRules.size(), expectedRevision, activeUaRules.size(), expectedUaRevision);
			return new FleetSyncResult(mitigationValves.size(), 0, activeRules.size(), expectedRevision, List.of());
		}

		Map<String, EndpointConfig> endpointsByName = new LinkedHashMap<>();
		for (EndpointConfig ep : properties.getEndpoints()) {
			if (ep != null && ep.isEnabled() && ep.getName() != null) {
				endpointsByName.put(ep.getName(), ep);
			}
		}

		int targetCount = mitigationValves.size();
		int syncedCount = 0;
		List<String> errors = new ArrayList<>();

		for (MonitoredValve valve : mitigationValves) {
			String valveKey = valve.serverId() + "/" + valve.valveName();
			EndpointConfig ep = endpointsByName.get(valve.serverId());
			if (ep == null) {
				continue;
			}
			try {
				String targetUrl = resolveMitigationUrl(ep, valve.mitigationUri());
				String token = resolveMitigationToken(ep);
				boolean includeUaPayload = uaRuleRepository != null
						&& (!activeUaRules.isEmpty() || valve.dynamicUaBlocksActiveCount() > 0 || valve.dynamicUaRulesRevision() != 0L);

				ValveStatusClient.MitigationCommandResponse resp = null;
				if (includeUaPayload) {
					resp = statusClient.sendMitigationCommand(
							targetUrl,
							token,
							valve.valveName(),
							"replace",
							null,
							null,
							null,
							blocksPayload,
							uaBlocksPayload
					);
				}
				if (resp == null) {
					resp = statusClient.sendMitigationCommand(
							targetUrl,
							token,
							valve.valveName(),
							"replace",
							null,
							null,
							null,
							blocksPayload
					);
				}
				if (includeUaPayload || resp.dynamicUaBlocksActiveCount() != null || resp.dynamicUaRulesRevision() != null) {
					valveRepository.updateDynamicMitigationStats(
							valve.serverId(),
							valve.valveName(),
							true,
							valve.mitigationUri(),
							resp.activeCount(),
							valve.dynamicBlocksBlockedRequests(),
							resp.revision(),
							resp.dynamicRulesHashVersionOrDefault(),
							resp.dynamicUaBlocksActiveCountOrDefault(),
							valve.dynamicUaBlocksBlockedRequests(),
							valve.dynamicUaBlocksBypassedRequests(),
							resp.dynamicUaRulesRevisionOrDefault(),
							now
					);
				} else {
					valveRepository.updateDynamicMitigationStats(
							valve.serverId(),
							valve.valveName(),
							true,
							valve.mitigationUri(),
							resp.activeCount(),
							valve.dynamicBlocksBlockedRequests(),
							resp.revision(),
							resp.dynamicRulesHashVersionOrDefault(),
							now
					);
				}
				syncedCount++;

				boolean cidrMatch = (resp.revision() == expectedRevision);
				boolean uaMatch = !includeUaPayload
						|| resp.dynamicUaRulesRevision() == null
						|| resp.dynamicUaRulesRevisionOrDefault() == expectedUaRevision;

				if (cidrMatch && uaMatch) {
					valveSyncStates.remove(valveKey);
				} else {
					long trackedExpected = expectedUaRevision == 0L ? expectedRevision : (expectedRevision ^ (expectedUaRevision * 31L));
					long trackedReported = expectedUaRevision == 0L ? resp.revision() : (resp.revision() ^ (resp.dynamicUaRulesRevisionOrDefault() * 31L));
					String reason = "Revision mismatch after fleet sync: expected CIDR rev " + expectedRevision
							+ (includeUaPayload ? " / UA rev " + expectedUaRevision : "")
							+ ", but valve reported CIDR rev " + resp.revision()
							+ (includeUaPayload ? " / UA rev " + resp.dynamicUaRulesRevisionOrDefault() : "");
					Instant backoffUntil = now.plus(Duration.ofMinutes(15));
					valveSyncStates.put(valveKey, new ValveSyncState(trackedExpected, trackedReported, 1, now, backoffUntil, reason));
					recordAudit(null, valveKey, "SYNC_CIRCUIT_BREAKER",
							"Fleet sync completed but resulting revision (CIDR " + resp.revision()
									+ (includeUaPayload ? ", UA " + resp.dynamicUaRulesRevisionOrDefault() : "")
									+ ") differs from expected (CIDR " + expectedRevision
									+ (includeUaPayload ? ", UA " + expectedUaRevision : "")
									+ "). Active rules: " + resp.activeCount() + " CIDR, "
									+ resp.dynamicUaBlocksActiveCountOrDefault() + " UA. Auto-sync suspended for 15m to prevent loop.",
							0, "ADMIN");
				}

				if (resp.ttlCappedCountOrDefault() > 0) {
					log.info("Valve '{}/{}' capped TTL for {} dynamic block(s) to mitigationMaxTtlSeconds={}s",
							valve.serverId(), valve.valveName(), resp.ttlCappedCountOrDefault(), resp.mitigationMaxTtlSecondsOrDefault());
				}
			} catch (IOException | InterruptedException | RuntimeException e) {
				String err = valve.serverId() + "/" + valve.valveName() + ": " + ValveStatusClient.formatErrorMessage(e);
				log.warn("Failed to sync dynamic mitigations to '{}': {}", valve.serverId() + "/" + valve.valveName(), e.getMessage());
				errors.add(err);
				long trackedExpected = expectedUaRevision == 0L ? expectedRevision : (expectedRevision ^ (expectedUaRevision * 31L));
				long trackedValve = expectedUaRevision == 0L ? valve.dynamicRulesRevision() : (valve.dynamicRulesRevision() ^ (valve.dynamicUaRulesRevision() * 31L));
				Instant backoffUntil = now.plus(Duration.ofMinutes(5));
				valveSyncStates.put(valveKey, new ValveSyncState(trackedExpected, trackedValve, 1, now, backoffUntil, err));
			}
		}

		if (targetCount > 0) {
			recordAudit(null, "FLEET", "FLEET_SYNC",
					"Fleet sync completed: " + syncedCount + "/" + targetCount + " valve(s) synced, "
							+ activeRules.size() + " active CIDR rule(s) (rev: " + expectedRevision + ")"
							+ (uaRuleRepository != null ? ", " + activeUaRules.size() + " active UA rule(s) (rev: " + expectedUaRevision + ")" : "")
							+ (errors.isEmpty() ? "" : ", errors: " + errors.size()),
					0, "ADMIN");
		}

		return new FleetSyncResult(targetCount, syncedCount, activeRules.size(), expectedRevision, errors);
	}

	/**
	 * Called during the poller cycle when a Valve advertises {@code dynamicMitigationEnabled = true}.
	 * Automatically reconciles the Valve's in-memory registry if its {@code dynamicRulesRevision}
	 * or {@code dynamicUaRulesRevision} differs from the Collector's expected revision (e.g. after a Tomcat restart).
	 * <p>
	 * Protected by a smart revision-scoped circuit breaker to prevent infinite update loops
	 * across divergent hash versions or guardrail rejections.
	 */
	public void syncValveIfNeeded(EndpointConfig endpoint, ValveOverviewDto.ValveSummaryDto valveSummary, Instant now) {
		if (!properties.getMode().isBackgroundProcessingEnabled()
				|| endpoint == null || valveSummary == null || !valveSummary.dynamicMitigationEnabledOrDefault()) {
			return;
		}
		String valveKey = endpoint.getName() + "/" + valveSummary.monitorName();
		long expectedRevision = getExpectedRevision(now);
		long valveRevision = valveSummary.dynamicRulesRevisionOrDefault();
		int valveHashVersion = valveSummary.dynamicRulesHashVersionOrDefault();

		long expectedUaRevision = getExpectedUaRevision(now);
		long valveUaRevision = valveSummary.dynamicUaRulesRevisionOrDefault();
		boolean includeUaPayload = uaRuleRepository != null
				&& (!getActiveUaRulesForSync(now).isEmpty() || valveUaRevision != 0L || valveSummary.dynamicUaBlocksActiveCountOrDefault() > 0);

		boolean cidrConverged = (valveRevision == expectedRevision);
		boolean uaConverged = !includeUaPayload || (valveUaRevision == expectedUaRevision);

		long trackedExpected = expectedUaRevision == 0L ? expectedRevision : (expectedRevision ^ (expectedUaRevision * 31L));
		long trackedValve = expectedUaRevision == 0L ? valveRevision : (valveRevision ^ (valveUaRevision * 31L));

		if (cidrConverged && uaConverged) {
			ValveSyncState prev = valveSyncStates.remove(valveKey);
			if (prev != null && prev.consecutiveMismatches() > 0) {
				log.info("Dynamic rule revision converged for '{}/{}' (CIDR rev: {}, UA rev: {})",
						endpoint.getName(), valveSummary.monitorName(), expectedRevision, expectedUaRevision);
				recordAudit(null, valveKey, "SYNC_RECOVERED",
						"Dynamic rules revision converged with Collector (CIDR rev: " + expectedRevision
								+ (expectedUaRevision != 0L ? ", UA rev: " + expectedUaRevision : "") + ")",
						0, "AUTO_POLLER");
			}
			return;
		}

		// 1. Check Circuit Breaker suppression:
		// Only suppress if the rule set hasn't changed (attemptedExpectedRevision == trackedExpected)
		// and we are still in the backoff window.
		ValveSyncState existingState = valveSyncStates.get(valveKey);
		if (existingState != null && existingState.isSuppressed(trackedExpected, now)) {
			if (log.isDebugEnabled()) {
				log.debug("Auto-sync to '{}/{}' suppressed by circuit breaker until {} (expectedCIDR: {}, valveCIDR: {}, expectedUA: {}, valveUA: {})",
						endpoint.getName(), valveSummary.monitorName(), existingState.backoffUntil(),
						expectedRevision, valveRevision, expectedUaRevision, valveUaRevision);
			}
			return;
		}

		// 2. Hash version compatibility check:
		if (valveHashVersion != CURRENT_HASH_VERSION) {
			String reason = "Incompatible hash version: Valve reports " + valveHashVersion + " but Collector expects " + CURRENT_HASH_VERSION;
			log.warn("Auto-sync skipped for '{}/{}': {}", endpoint.getName(), valveSummary.monitorName(), reason);
			Instant backoffUntil = now.plus(Duration.ofMinutes(15));
			valveSyncStates.put(valveKey, new ValveSyncState(trackedExpected, trackedValve, 1, now, backoffUntil, reason));
			recordAudit(null, valveKey, "SYNC_VERSION_MISMATCH", reason, 0, "AUTO_POLLER");
			return;
		}

		List<MitigationRule> activeRules = getActiveRulesForSync(now);
		String blocksPayload = buildBlocksPayload(activeRules);
		List<MitigationUaRule> activeUaRules = getActiveUaRulesForSync(now);
		String uaBlocksPayload = buildUaBlocksPayload(activeUaRules);
		String targetUrl = resolveMitigationUrl(endpoint, valveSummary.mitigationUri());
		String token = resolveMitigationToken(endpoint);

		try {
			ValveStatusClient.MitigationCommandResponse resp = null;
			if (includeUaPayload) {
				resp = statusClient.sendMitigationCommand(
						targetUrl,
						token,
						valveSummary.monitorName(),
						"replace",
						null,
						null,
						null,
						blocksPayload,
						uaBlocksPayload
				);
			}
			if (resp == null) {
				resp = statusClient.sendMitigationCommand(
						targetUrl,
						token,
						valveSummary.monitorName(),
						"replace",
						null,
						null,
						null,
						blocksPayload
				);
			}
			if (includeUaPayload || resp.dynamicUaBlocksActiveCount() != null || resp.dynamicUaRulesRevision() != null) {
				valveRepository.updateDynamicMitigationStats(
						endpoint.getName(),
						valveSummary.monitorName(),
						true,
						valveSummary.mitigationUri(),
						resp.activeCount(),
						valveSummary.dynamicBlocksBlockedRequestsOrDefault(),
						resp.revision(),
						resp.dynamicRulesHashVersionOrDefault(),
						resp.dynamicUaBlocksActiveCountOrDefault(),
						valveSummary.dynamicUaBlocksBlockedRequestsOrDefault(),
						valveSummary.dynamicUaBlocksBypassedRequestsOrDefault(),
						resp.dynamicUaRulesRevisionOrDefault(),
						now
				);
			} else {
				valveRepository.updateDynamicMitigationStats(
						endpoint.getName(),
						valveSummary.monitorName(),
						true,
						valveSummary.mitigationUri(),
						resp.activeCount(),
						valveSummary.dynamicBlocksBlockedRequestsOrDefault(),
						resp.revision(),
						resp.dynamicRulesHashVersionOrDefault(),
						now
				);
			}

			boolean syncedCidrOk = (resp.revision() == expectedRevision);
			boolean syncedUaOk = !includeUaPayload
					|| resp.dynamicUaRulesRevision() == null
					|| resp.dynamicUaRulesRevisionOrDefault() == expectedUaRevision;

			if (syncedCidrOk && syncedUaOk) {
				ValveSyncState prev = valveSyncStates.remove(valveKey);
				if (prev != null && prev.consecutiveMismatches() > 0) {
					recordAudit(null, valveKey, "SYNC_RECOVERED",
							"Dynamic rules revision converged with Collector (CIDR rev: " + expectedRevision
									+ (includeUaPayload ? ", UA rev: " + expectedUaRevision : "") + ")",
							0, "AUTO_POLLER");
				}
				log.info("Auto-synchronized {} CIDR and {} UA dynamic rule(s) to '{}/{}' (CIDR {} -> {}, UA {} -> {})",
						resp.activeCount(), resp.dynamicUaBlocksActiveCountOrDefault(),
						endpoint.getName(), valveSummary.monitorName(),
						valveRevision, resp.revision(), valveUaRevision, resp.dynamicUaRulesRevisionOrDefault());
			} else {
				// Divergence detected immediately after replace!
				int consecutive = (existingState != null ? existingState.consecutiveMismatches() : 0) + 1;
				long backoffMinutes = consecutive == 1 ? 5L : 15L;
				Instant backoffUntil = now.plus(Duration.ofMinutes(backoffMinutes));
				long reportedUa = resp.dynamicUaRulesRevisionOrDefault();
				long trackedReported = expectedUaRevision == 0L ? resp.revision() : (resp.revision() ^ (reportedUa * 31L));
				String reason = "Revision mismatch after sync: expected CIDR " + expectedRevision
						+ (includeUaPayload ? " / UA " + expectedUaRevision : "")
						+ ", but valve reported CIDR " + resp.revision()
						+ (includeUaPayload ? " / UA " + reportedUa : "");
				valveSyncStates.put(valveKey, new ValveSyncState(trackedExpected, trackedReported, consecutive, now, backoffUntil, reason));

				log.warn("Dynamic rule revision mismatch for valve '{}/{}' after auto-sync ({}). "
						+ "Suspected hash algorithm or version mismatch. Auto-sync suspended for {}m for this rule set.",
						endpoint.getName(), valveSummary.monitorName(), reason, backoffMinutes);

				recordAudit(null, valveKey, "SYNC_CIRCUIT_BREAKER",
						"Auto-sync completed but resulting revision differs (" + reason + "). Active rules: "
								+ resp.activeCount() + " CIDR, " + resp.dynamicUaBlocksActiveCountOrDefault()
								+ " UA. Auto-sync suspended for " + backoffMinutes + "m to prevent loop.",
						0, "AUTO_POLLER");
			}

			if (resp.ttlCappedCountOrDefault() > 0) {
				log.info("Valve '{}/{}' capped TTL for {} dynamic block(s) to mitigationMaxTtlSeconds={}s",
						endpoint.getName(), valveSummary.monitorName(), resp.ttlCappedCountOrDefault(), resp.mitigationMaxTtlSecondsOrDefault());
			}
		} catch (Exception e) {
			int consecutive = (existingState != null ? existingState.consecutiveMismatches() : 0) + 1;
			long backoffMinutes = consecutive == 1 ? 2L : 10L;
			Instant backoffUntil = now.plus(Duration.ofMinutes(backoffMinutes));
			String errMsg = ValveStatusClient.formatErrorMessage(e);
			valveSyncStates.put(valveKey, new ValveSyncState(trackedExpected, trackedValve, consecutive, now, backoffUntil, errMsg));

			log.warn("Auto-sync of dynamic rules to '{}/{}' failed: {}. Retries suspended for {}m.",
					endpoint.getName(), valveSummary.monitorName(), errMsg, backoffMinutes);

			recordAudit(null, valveKey, "SYNC_FAILED",
					"Auto-sync failed: " + errMsg + ". Retries suspended for " + backoffMinutes + "m.",
					0, "AUTO_POLLER");
		}
	}

	public boolean isValveSyncSuppressed(String serverId, String valveName, long currentExpectedRevision, Instant now) {
		String key = serverId + "/" + valveName;
		ValveSyncState state = valveSyncStates.get(key);
		return state != null && state.isSuppressed(currentExpectedRevision, now);
	}

	public Optional<ValveSyncState> getValveSyncState(String serverId, String valveName) {
		return Optional.ofNullable(valveSyncStates.get(serverId + "/" + valveName));
	}

	public void resetCircuitBreaker(String serverId, String valveName) {
		if (serverId != null && valveName != null) {
			valveSyncStates.remove(serverId + "/" + valveName);
		} else {
			valveSyncStates.clear();
		}
	}

	public String resolveMitigationUrl(EndpointConfig endpoint, String valveMitigationUri) {
		if (endpoint.getMitigationUrl() != null && !endpoint.getMitigationUrl().isBlank()) {
			return endpoint.getMitigationUrl().trim();
		}
		String baseUrl = endpoint.getUrl();
		if (valveMitigationUri != null && !valveMitigationUri.isBlank() && baseUrl != null) {
			try {
				URI base = URI.create(baseUrl);
				String path = valveMitigationUri.startsWith("/") ? valveMitigationUri : "/" + valveMitigationUri;
				return new URI(base.getScheme(), base.getUserInfo(), base.getHost(), base.getPort(), path, null, null).toString();
			} catch (Exception ignored) {
			}
		}
		return baseUrl;
	}

	public String resolveMitigationToken(EndpointConfig endpoint) {
		if (endpoint.getMitigationToken() != null && !endpoint.getMitigationToken().isBlank()) {
			return endpoint.getMitigationToken().trim();
		}
		if (properties.getMitigationToken() != null && !properties.getMitigationToken().isBlank()) {
			return properties.getMitigationToken().trim();
		}
		return endpoint.getToken();
	}

	private static final int MAX_VALVE_LABEL_LENGTH = 64;

	/**
	 * Builds the {@code cidr|expiresAtMillis|label} payload pushed to the Valves.
	 * <p>
	 * The full rule reason stays in the Collector database. Valves only receive a compact, sanitized label
	 * because the payload is re-sent on every fleet sync and echoed back in every status poll. The label must
	 * never contain {@code |}, line breaks or {@code ;} (the Valve splits block lines on {@code ;}).
	 */
	static String buildBlocksPayload(List<MitigationRule> activeRules) {
		if (activeRules == null || activeRules.isEmpty()) {
			return "";
		}
		StringBuilder sb = new StringBuilder(activeRules.size() * 48);
		for (MitigationRule r : activeRules) {
			sb.append(r.cidr())
					.append('|')
					.append(r.expiresAt().toEpochMilli())
					.append('|')
					.append(compactValveLabel(r))
					.append('\n');
		}
		return sb.toString();
	}

	static String compactValveLabel(MitigationRule r) {
		String source = (r.source() != null && !r.source().isBlank()) ? r.source().trim() : MitigationRule.SOURCE_MANUAL;
		boolean autoRule = MitigationRule.SOURCE_AUTO_CARPET.equalsIgnoreCase(source)
				|| MitigationRule.SOURCE_AUTO_RULE.equalsIgnoreCase(source);
		String label;
		if (autoRule && r.asn() != null) {
			label = source + " AS" + r.asn();
		} else {
			label = (r.reason() != null && !r.reason().isBlank()) ? r.reason().trim() : "Dynamic Mitigation";
		}
		label = label.replace('|', '/').replace('\n', ' ').replace('\r', ' ').replace(';', ',');
		if (label.length() > MAX_VALVE_LABEL_LENGTH) {
			label = label.substring(0, MAX_VALVE_LABEL_LENGTH - 3).trim() + "...";
		}
		return label;
	}

	/**
	 * Builds the {@code uaHash32|expiresAtMillis|label} payload pushed to the Valves.
	 */
	static String buildUaBlocksPayload(List<MitigationUaRule> activeRules) {
		if (activeRules == null || activeRules.isEmpty()) {
			return "";
		}
		StringBuilder sb = new StringBuilder(activeRules.size() * 48);
		for (MitigationUaRule r : activeRules) {
			sb.append(r.uaHash32())
					.append('|')
					.append(r.expiresAt().toEpochMilli())
					.append('|')
					.append(compactValveUaLabel(r))
					.append('\n');
		}
		return sb.toString();
	}

	static String compactValveUaLabel(MitigationUaRule r) {
		String source = (r.source() != null && !r.source().isBlank()) ? r.source().trim() : MitigationUaRule.SOURCE_MANUAL;
		String label = (r.reason() != null && !r.reason().isBlank())
				? source + ": " + r.reason().trim()
				: (r.uaHash32() == 0 ? source + ": Block Empty / Missing UA" : source + " UA Block");
		label = label.replace('|', '/').replace('\n', ' ').replace('\r', ' ').replace(';', ',');
		if (label.length() > MAX_VALVE_LABEL_LENGTH) {
			label = label.substring(0, MAX_VALVE_LABEL_LENGTH - 3).trim() + "...";
		}
		return label;
	}

	// =========================================================================
	// Attacker Deterrence Tracking & Evaluation
	// =========================================================================

	/**
	 * Signals a non-blocking Virtual Thread to evaluate attacker deterrence metrics
	 * for all active dynamic mitigation rules.
	 */
	public void refreshDeterrenceMetricsAsync() {
		if (properties.isViewerMode()) {
			return;
		}
		deterrenceRefreshPending.set(true);
		if (deterrenceWorkerRunning.compareAndSet(false, true)) {
			Thread.ofVirtual().name("mitigation-deterrence-worker").start(() -> {
				try {
					while (deterrenceRefreshPending.getAndSet(false)) {
						try {
							Thread.sleep(500L);
						} catch (InterruptedException e) {
							Thread.currentThread().interrupt();
							break;
						}
						refreshDeterrenceMetrics();
					}
				} catch (Throwable t) {
					log.debug("Deterrence telemetry refresh error: {}", t.getMessage());
				} finally {
					deterrenceWorkerRunning.set(false);
					if (deterrenceRefreshPending.get()) {
						refreshDeterrenceMetricsAsync();
					}
				}
			});
		}
	}

	/**
	 * Refreshes deterrence metrics synchronously if the last refresh is older than {@code maxAge},
	 * otherwise triggers an asynchronous background refresh so UI requests remain fast.
	 */
	public void refreshDeterrenceMetricsIfStale(Duration maxAge) {
		if (properties.isViewerMode()) {
			return;
		}
		long ageMs = System.currentTimeMillis() - lastDeterrenceRefreshMillis;
		if (lastDeterrenceRefreshMillis == 0L || ageMs >= maxAge.toMillis()) {
			refreshDeterrenceMetrics();
		} else {
			refreshDeterrenceMetricsAsync();
		}
	}

	public void refreshDeterrenceMetrics() {
		if (properties.isViewerMode()) {
			return;
		}
		Instant now = Instant.now();
		ruleRepository.expireElapsedRules(now);
		List<MitigationRule> activeRules = ruleRepository.findActiveRules(now);
		lastDeterrenceRefreshMillis = System.currentTimeMillis();
		if (!activeRules.isEmpty()) {
			refreshCidrDeterrenceMetrics(activeRules, now);
		}
		refreshUaDeterrenceMetrics(now);
	}

	private void refreshCidrDeterrenceMetrics(List<MitigationRule> activeRules, Instant now) {
		Instant recentCutoff = now.minusSeconds(DETERRENCE_WINDOW_SECONDS);
		Map<String, List<MitigationRule>> rulesByCidr = new HashMap<>(activeRules.size() * 2);
		Instant earliestCutoff = null;
		for (MitigationRule rule : activeRules) {
			rulesByCidr.computeIfAbsent(rule.cidr(), k -> new ArrayList<>(1)).add(rule);
			Instant ruleCutoff = rule.createdAt().minusSeconds(60);
			if (earliestCutoff == null || ruleCutoff.isBefore(earliestCutoff)) {
				earliestCutoff = ruleCutoff;
			}
		}

		Map<Long, DeterrenceStatsAccumulator> statsByRuleId = new HashMap<>();
		try {
			jdbcTemplate.query("""
					SELECT client_key, slot_time, request_count, distinct_clients, last_updated_at
					FROM client_events
					WHERE status = 'BLOCKED'
					  AND slot_time >= ?
					""",
					rs -> {
						String clientKey = rs.getString("client_key");
						List<MitigationRule> matched = rulesByCidr.get(clientKey);
						if (matched == null) {
							return;
						}
						Instant slotTime = toInstant(rs.getObject("slot_time"));
						long reqCount = rs.getLong("request_count");
						int distinctClients = rs.getInt("distinct_clients");
						Instant lastUpdated = toInstant(rs.getObject("last_updated_at"));
						for (MitigationRule rule : matched) {
							if (slotTime == null || !slotTime.isBefore(rule.createdAt().minusSeconds(60))) {
								statsByRuleId.computeIfAbsent(rule.id(), k -> new DeterrenceStatsAccumulator())
										.accept(reqCount, distinctClients, lastUpdated);
							}
						}
					},
					Timestamp.from(earliestCutoff));
		} catch (Exception e) {
			log.debug("Could not batch-query deterrence stats: {}", e.getMessage());
			return;
		}

		List<MitigationRuleRepository.DeterrenceUpdate> updates = new ArrayList<>();
		for (MitigationRule rule : activeRules) {
			DeterrenceStatsAccumulator acc = statsByRuleId.get(rule.id());
			long totalHits = acc != null ? acc.totalHits : 0L;
			int peakIps = acc != null ? acc.peakIps : 0;
			Instant lastHit = acc != null ? acc.lastHit : null;

			long effectiveHits = Math.max(rule.totalBlockedHits(), totalHits);
			int effectivePeakIps = Math.max(rule.peakDistinctIps(), peakIps);
			Instant effectiveLastHit = (lastHit != null && (rule.lastHitAt() == null || lastHit.isAfter(rule.lastHitAt())))
					? lastHit
					: rule.lastHitAt();

			String state;
			if (effectiveLastHit != null && effectiveLastHit.isAfter(recentCutoff) && effectiveHits > 0) {
				state = MitigationRule.DETERRENCE_PERSISTENT;
			} else if (rule.createdAt().isBefore(recentCutoff)) {
				state = MitigationRule.DETERRENCE_DETERRED;
			} else {
				state = MitigationRule.DETERRENCE_OBSERVING;
			}

			if (effectiveHits != rule.totalBlockedHits()
					|| effectivePeakIps != rule.peakDistinctIps()
					|| !Objects.equals(effectiveLastHit, rule.lastHitAt())
					|| !Objects.equals(state, rule.deterrenceState())) {
				updates.add(new MitigationRuleRepository.DeterrenceUpdate(
						rule.id(), effectiveHits, effectivePeakIps, effectiveLastHit, state));
			}
		}

		if (!updates.isEmpty()) {
			ruleRepository.batchUpdateDeterrenceTelemetry(updates, now);
		}
	}

	private void refreshUaDeterrenceMetrics(Instant now) {
		if (uaRuleRepository == null) {
			return;
		}
		uaRuleRepository.expireElapsedRules(now);
		List<MitigationUaRule> activeUaRules = uaRuleRepository.findActiveRules(now);
		if (activeUaRules.isEmpty()) {
			return;
		}

		Map<String, List<MitigationUaRule>> rulesBySyntheticKey = new HashMap<>(activeUaRules.size() * 2);
		Map<String, List<MitigationUaRule>> rulesByRawUa = new HashMap<>(activeUaRules.size() * 2);
		Instant earliestCutoff = null;
		for (MitigationUaRule rule : activeUaRules) {
			rulesBySyntheticKey.computeIfAbsent("UA:" + rule.uaHash32(), k -> new ArrayList<>(1)).add(rule);
			if (rule.rawUserAgent() != null && !rule.rawUserAgent().isBlank() && !"<EMPTY>".equalsIgnoreCase(rule.rawUserAgent().trim())) {
				rulesByRawUa.computeIfAbsent(rule.rawUserAgent().trim(), k -> new ArrayList<>(1)).add(rule);
			} else {
				rulesByRawUa.computeIfAbsent("", k -> new ArrayList<>(1)).add(rule);
			}
			Instant ruleCutoff = rule.createdAt().minusSeconds(60);
			if (earliestCutoff == null || ruleCutoff.isBefore(earliestCutoff)) {
				earliestCutoff = ruleCutoff;
			}
		}

		if (earliestCutoff == null) {
			return;
		}

		Map<Long, DeterrenceStatsAccumulator> statsByRuleId = new HashMap<>();
		try {
			jdbcTemplate.query("""
					SELECT client_key, sample_user_agent, slot_time, request_count, last_updated_at
					FROM client_events
					WHERE status = 'BLOCKED'
					  AND slot_time >= ?
					""",
					rs -> {
						String clientKey = rs.getString("client_key");
						String sampleUa = rs.getString("sample_user_agent");
						List<MitigationUaRule> matched = null;
						if (IpNetworkUtil.isSyntheticUaKey(clientKey)) {
							matched = rulesBySyntheticKey.get(clientKey.trim());
						} else if (sampleUa != null && !sampleUa.isBlank()) {
							matched = rulesByRawUa.get(sampleUa.trim());
						}
						if (matched == null || matched.isEmpty()) {
							return;
						}
						Instant slotTime = toInstant(rs.getObject("slot_time"));
						long reqCount = rs.getLong("request_count");
						Instant lastUpdated = toInstant(rs.getObject("last_updated_at"));
						for (MitigationUaRule rule : matched) {
							if (slotTime == null || !slotTime.isBefore(rule.createdAt().minusSeconds(60))) {
								statsByRuleId.computeIfAbsent(rule.id(), k -> new DeterrenceStatsAccumulator())
										.accept(reqCount, 1, lastUpdated);
							}
						}
					},
					Timestamp.from(earliestCutoff));
		} catch (Exception e) {
			log.debug("Could not batch-query UA deterrence stats: {}", e.getMessage());
			return;
		}

		Instant recentCutoff = now.minusSeconds(DETERRENCE_WINDOW_SECONDS);
		List<MitigationUaRuleRepository.UaDeterrenceUpdate> uaUpdates = new ArrayList<>();
		for (MitigationUaRule rule : activeUaRules) {
			DeterrenceStatsAccumulator acc = statsByRuleId.get(rule.id());
			long totalHits = acc != null ? acc.totalHits : 0L;
			Instant lastHit = acc != null ? acc.lastHit : null;

			long effectiveHits = Math.max(rule.totalBlockedHits(), totalHits);
			Instant effectiveLastHit = (lastHit != null && (rule.lastHitAt() == null || lastHit.isAfter(rule.lastHitAt())))
					? lastHit
					: rule.lastHitAt();

			String state;
			if (effectiveLastHit != null && effectiveLastHit.isAfter(recentCutoff) && effectiveHits > 0) {
				state = MitigationUaRule.DETERRENCE_PERSISTENT;
			} else if (rule.createdAt().isBefore(recentCutoff)) {
				state = MitigationUaRule.DETERRENCE_DETERRED;
			} else {
				state = MitigationUaRule.DETERRENCE_OBSERVING;
			}

			if (effectiveHits != rule.totalBlockedHits()
					|| !Objects.equals(effectiveLastHit, rule.lastHitAt())
					|| !Objects.equals(state, rule.deterrenceState())) {
				uaUpdates.add(new MitigationUaRuleRepository.UaDeterrenceUpdate(
						rule.id(), effectiveHits, rule.totalBypassedHits(), effectiveLastHit, state));
			}
		}

		if (!uaUpdates.isEmpty()) {
			uaRuleRepository.batchUpdateDeterrenceTelemetry(uaUpdates, now);
		}
	}

	private static final class DeterrenceStatsAccumulator {
		long totalHits;
		int peakIps;
		Instant lastHit;

		void accept(long hits, int distinctClients, Instant updated) {
			this.totalHits += hits;
			if (distinctClients > this.peakIps) {
				this.peakIps = distinctClients;
			}
			if (updated != null && (this.lastHit == null || updated.isAfter(this.lastHit))) {
				this.lastHit = updated;
			}
		}
	}

	public List<MitigationRule> getActiveRules() {
		Instant now = Instant.now();
		if (!properties.isViewerMode()) {
			ruleRepository.expireElapsedRules(now);
		}
		return ruleRepository.findActiveRules(now);
	}

	// =========================================================================
	// Coalesced Fleet Synchronization
	// =========================================================================

	/**
	 * Executes the given action while coalescing all fleet sync requests issued on the current thread.
	 * Exactly one {@code replace} push with the final rule set is performed when the outermost scope ends
	 * (and only if at least one sync was requested). Scopes may be nested.
	 */
	public <T> T callWithDeferredFleetSync(java.util.function.Supplier<T> action) {
		DeferredSyncState state = deferredFleetSync.get();
		if (state == null) {
			state = new DeferredSyncState();
			deferredFleetSync.set(state);
		}
		state.depth++;
		try {
			return action.get();
		} finally {
			state.depth--;
			if (state.depth == 0) {
				deferredFleetSync.remove();
				if (state.pending) {
					try {
						syncFleetMitigations();
					} catch (RuntimeException e) {
						log.warn("Coalesced fleet mitigation sync failed: {}", e.getMessage());
					}
				}
			}
		}
	}

	public void runWithDeferredFleetSync(Runnable action) {
		callWithDeferredFleetSync(() -> {
			action.run();
			return null;
		});
	}

	// =========================================================================
	// Capacity Management: Releasing Unused Autonomous Rules
	// =========================================================================

	/**
	 * Counts active autonomous rules that never blocked a request after their observation phase.
	 */
	public int countUnusedAutoRules(int limit) {
		if (limit <= 0) {
			return 0;
		}
		Instant now = Instant.now();
		return ruleRepository.findUnusedAutoRules(now, now.minusSeconds(OBSERVATION_WINDOW_SECONDS), limit).size();
	}

	/**
	 * Releases up to {@code maxToRelease} active autonomous rules that have not blocked a single request since
	 * their activation (observation phase elapsed, oldest first) to make room for higher-priority candidates.
	 * The regular TTL remains the only lifetime of a rule; this release only happens under capacity pressure.
	 *
	 * @return Number of released rules
	 */
	public int releaseUnusedAutoRules(int maxToRelease, String reason, String actor) {
		requireWriteMode("Releasing unused mitigation rules");
		if (maxToRelease <= 0) {
			return 0;
		}
		Instant now = Instant.now();
		List<MitigationRule> victims = ruleRepository.findUnusedAutoRules(
				now, now.minusSeconds(OBSERVATION_WINDOW_SECONDS), maxToRelease);
		if (victims.isEmpty()) {
			return 0;
		}
		String safeReason = (reason != null && !reason.isBlank()) ? reason.trim()
				: "Released unused rule to free capacity for higher-priority subnets";
		int released = ruleRepository.revokeRulesByIds(victims.stream().map(MitigationRule::id).toList(), now, safeReason);
		if (released > 0) {
			ruleRepository.insertAuditEntry(new MitigationAuditEntry(
					null,
					victims.getFirst().id(),
					released + " unused rules (" + victims.getFirst().cidr() + "...)",
					null,
					"AUTO_RELEASE_UNUSED",
					actor != null ? actor : "AUTO_ENGINE",
					0,
					safeReason + " [" + released + " rules without blocked hits]",
					now
			));
			log.info("Released {} unused autonomous rule(s) to free capacity (oldest: {})", released, victims.getFirst().cidr());
			syncFleetMitigations();
		}
		return released;
	}

	public record PruneToCapResult(
			int beforeCount,
			int afterCount,
			int targetCap,
			int revokedCount,
			int revokedUnusedCount,
			int revokedDeterredCount,
			int revokedObservingCount,
			int revokedPersistentCount
	) {}

	/**
	 * Immediately trims all active mitigation rules down to {@code targetCap} using an optimal eviction
	 * cascade (0-hit unused past observation window, then deterred, then observing, and finally lowest-hit
	 * persistent attackers; autonomous rules before ASN_BATCH/other before MANUAL within each tier).
	 */
	public PruneToCapResult pruneActiveRulesToCap(int targetCap, String actor) {
		requireWriteMode("Pruning active mitigation rules to cap");
		int safeCap = Math.max(0, targetCap);
		refreshDeterrenceMetrics();
		Instant now = Instant.now();
		List<MitigationRule> activeRules = new ArrayList<>(ruleRepository.findActiveRules(now));
		int beforeCount = activeRules.size();
		if (beforeCount <= safeCap) {
			return new PruneToCapResult(beforeCount, beforeCount, safeCap, 0, 0, 0, 0, 0);
		}

		activeRules.sort(evictionOrderComparator(now));
		List<MitigationRule> victims = activeRules.subList(0, beforeCount - safeCap);

		int unusedCount = 0;
		int deterredCount = 0;
		int observingCount = 0;
		int persistentCount = 0;
		for (MitigationRule v : victims) {
			switch (evictionActivityTier(v, now)) {
				case 0 -> unusedCount++;
				case 1 -> deterredCount++;
				case 2, 3 -> observingCount++;
				default -> persistentCount++;
			}
		}

		String reason = "Pruned to circuit breaker cap of " + safeCap + " active rules (optimal eviction priority)";
		int revoked = ruleRepository.revokeRulesByIds(victims.stream().map(MitigationRule::id).toList(), now, reason);
		if (revoked > 0) {
			ruleRepository.insertAuditEntry(new MitigationAuditEntry(
					null,
					victims.getFirst().id(),
					revoked + " excess rules (" + victims.getFirst().cidr() + "...)",
					null,
					"PRUNE_TO_CAP",
					actor != null ? actor : "ADMIN",
					0,
					"Trimmed active rules from " + beforeCount + " to cap " + (beforeCount - revoked)
							+ " (revoked " + revoked + ": " + unusedCount + " unused, " + deterredCount
							+ " deterred, " + observingCount + " observing, " + persistentCount + " persistent).",
					now
			));
			log.info("Pruned {} excess active mitigation rule(s) from {} to {} (cap {}): {} unused, {} deterred, {} observing, {} persistent",
					revoked, beforeCount, beforeCount - revoked, safeCap, unusedCount, deterredCount, observingCount, persistentCount);
			syncFleetMitigations();
		}
		return new PruneToCapResult(
				beforeCount,
				beforeCount - revoked,
				safeCap,
				revoked,
				unusedCount,
				deterredCount,
				observingCount,
				persistentCount
		);
	}

	static int evictionActivityTier(MitigationRule r, Instant now) {
		if (MitigationRule.DETERRENCE_PERSISTENT.equalsIgnoreCase(r.deterrenceState())) {
			return 4;
		}
		if (r.totalBlockedHits() <= 0
				&& (MitigationRule.DETERRENCE_DETERRED.equalsIgnoreCase(r.deterrenceState())
						|| (r.createdAt() != null && !r.createdAt().isAfter(now.minusSeconds(OBSERVATION_WINDOW_SECONDS))))) {
			return 0;
		}
		if (MitigationRule.DETERRENCE_DETERRED.equalsIgnoreCase(r.deterrenceState()) && r.totalBlockedHits() > 0) {
			return 1;
		}
		if (r.totalBlockedHits() <= 0) {
			return 2;
		}
		return 3;
	}

	static int evictionSourceTier(MitigationRule r) {
		String source = r.source();
		if (MitigationRule.SOURCE_AUTO_CARPET.equalsIgnoreCase(source)
				|| MitigationRule.SOURCE_AUTO_RULE.equalsIgnoreCase(source)) {
			return 0;
		}
		if (MitigationRule.SOURCE_MANUAL.equalsIgnoreCase(source)) {
			return 2;
		}
		return 1;
	}

	static Comparator<MitigationRule> evictionOrderComparator(Instant now) {
		return Comparator
				.comparingInt((MitigationRule r) -> evictionActivityTier(r, now))
				.thenComparingInt(MitigationService::evictionSourceTier)
				.thenComparingLong(MitigationRule::totalBlockedHits)
				.thenComparingInt(MitigationRule::peakDistinctIps)
				.thenComparing(MitigationRule::lastHitAt, Comparator.nullsFirst(Comparator.naturalOrder()))
				.thenComparing(MitigationRule::expiresAt, Comparator.nullsFirst(Comparator.naturalOrder()))
				.thenComparing(MitigationRule::id, Comparator.nullsFirst(Comparator.naturalOrder()));
	}

	public Optional<MitigationRule> getRuleById(long ruleId) {
		return ruleRepository.findById(ruleId);
	}

	public int countRecentAiBlockActions(Instant since) {
		int byActor = ruleRepository.countRecentBlockActionsByActorPrefix("AI_AGENT", since);
		int bySource = ruleRepository.countRecentRulesBySource(MitigationRule.SOURCE_AI_AGENT, since);
		return Math.max(byActor, bySource);
	}

	private void requireWriteMode(String operation) {
		if (properties.isViewerMode()) {
			throw new IllegalStateException(operation + " is disabled in read-only VIEWER mode.");
		}
	}

	public List<MitigationRule> getRecentRules(int limit) {
		return ruleRepository.findRecentRules(limit);
	}

	public List<MitigationRule> getHistoricalRulesFiltered(String search, String status, int offset, int limit) {
		return ruleRepository.findHistoricalRulesFiltered(search, status, offset, limit);
	}

	public long countHistoricalRulesFiltered(String search, String status) {
		return ruleRepository.countHistoricalRulesFiltered(search, status);
	}

	public List<MitigationAuditEntry> getAuditEntriesFiltered(String search, String action, String actor, int offset, int limit) {
		return ruleRepository.findAuditEntriesFiltered(search, action, actor, "ALL", offset, limit);
	}

	public List<MitigationAuditEntry> getAuditEntriesFiltered(String search, String action, String actor, String targetType, int offset, int limit) {
		return ruleRepository.findAuditEntriesFiltered(search, action, actor, targetType, offset, limit);
	}

	public long countAuditEntriesFiltered(String search, String action, String actor) {
		return ruleRepository.countAuditEntriesFiltered(search, action, actor, "ALL");
	}

	public long countAuditEntriesFiltered(String search, String action, String actor, String targetType) {
		return ruleRepository.countAuditEntriesFiltered(search, action, actor, targetType);
	}

	public List<MitigationAuditEntry> getRecentAuditEntries(int limit) {
		return ruleRepository.findRecentAuditEntries(limit);
	}

	public long getLatestAlertAuditId() {
		return ruleRepository.findLatestAlertAuditId();
	}

	public List<MitigationAuditEntry> getAlertEntriesSince(long sinceId, int limit) {
		return ruleRepository.findAlertEntriesSince(sinceId, limit);
	}

	public void recordAudit(Long ruleId, String cidr, String action, String details, Integer ttlSeconds, String actor) {
		recordAudit(ruleId, cidr, null, action, ttlSeconds, details, actor);
	}

	public void recordAudit(Long ruleId, String cidr, String batchId, String action, Integer ttlSeconds, String details, String actor) {
		ruleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, ruleId, cidr, batchId, action, actor != null ? actor : "AUTO-ENGINE", ttlSeconds, details, Instant.now(),
				MitigationAuditEntry.TARGET_CIDR
		));
	}

	public void recordUaAudit(Long ruleId, String targetLabel, String batchId, String action, Integer ttlSeconds, String details, String actor) {
		ruleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, ruleId, targetLabel, batchId, action, actor != null ? actor : "AUTO_UA_ENGINE", ttlSeconds, details, Instant.now(),
				MitigationAuditEntry.TARGET_USER_AGENT
		));
	}

	// =========================================================================
	// Dynamic User-Agent Mitigation: Pre-Flight, Manual Rules & Auto Engine
	// =========================================================================

	public static final String KEY_UA_AUTO_ENABLED = "mitigation.ua.auto.enabled";
	public static final String KEY_UA_AUTO_DRY_RUN = "mitigation.ua.auto.dry_run";
	public static final String KEY_UA_AUTO_DEFAULT_TTL_MINUTES = "mitigation.ua.auto.default_ttl_minutes";
	public static final String KEY_UA_AUTO_MAX_ACTIVE_RULES = "mitigation.ua.auto.max_active_rules";
	public static final String KEY_UA_AUTO_MIN_REQUESTS_24H = "mitigation.ua.auto.min_requests_24h";
	public static final String KEY_UA_AUTO_BLOCK_MANUAL_CANDIDATES = "mitigation.ua.auto.block_manual_candidates";
	public static final String KEY_UA_AUTO_BLOCK_PILLAR1_SPREAD = "mitigation.ua.auto.block_pillar1_spread";
	public static final String KEY_UA_AUTO_BLOCK_PILLAR2_CORRELATED = "mitigation.ua.auto.block_pillar2_correlated";
	public static final String KEY_UA_AUTO_BLOCK_PILLAR3_DATACENTER = "mitigation.ua.auto.block_pillar3_datacenter";
	public static final String KEY_UA_AUTO_BLOCK_SIGNATURE_ANOMALIES = "mitigation.ua.auto.block_signature_anomalies";

	public record UaPreflightCheckResult(
			String rawUserAgent,
			String userAgentHash,
			int uaHash32,
			String browserFamily,
			boolean valid,
			boolean alreadyBlocked,
			List<PreflightWarning> warnings,
			long observedRequests24h,
			long authenticatedRequests24h,
			int authenticatedSamples24h,
			String autoVerdict,
			String manualOverride,
			boolean safeToProceedWithoutOverride
	) {
		public boolean hasCriticalWarnings() {
			return warnings != null && warnings.stream().anyMatch(w -> "CRITICAL".equalsIgnoreCase(w.severity()));
		}

		public String hexHash32() { return String.format("0x%08x", uaHash32); }
		public String getRawUserAgent() { return rawUserAgent; }
		public String getUserAgentHash() { return userAgentHash; }
		public int getUaHash32() { return uaHash32; }
		public String getHexHash32() { return hexHash32(); }
		public String getBrowserFamily() { return browserFamily; }
		public boolean isValid() { return valid; }
		public boolean isAlreadyBlocked() { return alreadyBlocked; }
		public List<PreflightWarning> getWarnings() { return warnings; }
		public long getObservedRequests24h() { return observedRequests24h; }
		public long getAuthenticatedRequests24h() { return authenticatedRequests24h; }
		public int getAuthenticatedSamples24h() { return authenticatedSamples24h; }
		public String getAutoVerdict() { return autoVerdict; }
		public String getManualOverride() { return manualOverride; }
		public boolean isSafeToProceedWithoutOverride() { return safeToProceedWithoutOverride; }
	}

	public record EffectiveUaAutoSettings(
			boolean enabled,
			boolean dryRun,
			int defaultTtlMinutes,
			int maxActiveRules,
			long minRequests24h,
			boolean blockManualCandidates,
			boolean blockPillar1Spread,
			boolean blockPillar2Correlated,
			boolean blockPillar3Datacenter,
			boolean blockSignatureAnomalies,
			boolean hasDatabaseOverrides
	) {
		public boolean isEnabled() { return enabled; }
		public boolean isDryRun() { return dryRun; }
		public int getDefaultTtlMinutes() { return defaultTtlMinutes; }
		public int getMaxActiveRules() { return maxActiveRules; }
		public long getMinRequests24h() { return minRequests24h; }
		public boolean isBlockManualCandidates() { return blockManualCandidates; }
		public boolean isBlockPillar1Spread() { return blockPillar1Spread; }
		public boolean isBlockPillar2Correlated() { return blockPillar2Correlated; }
		public boolean isBlockPillar3Datacenter() { return blockPillar3Datacenter; }
		public boolean isBlockSignatureAnomalies() { return blockSignatureAnomalies; }
		public boolean isHasDatabaseOverrides() { return hasDatabaseOverrides; }
	}

	public record AutoUaEvaluationResult(
			int candidatesEvaluated,
			int rulesActivated,
			int dryRunLogged,
			int skippedProtected
	) {}

	public static String formatUaAuditTarget(int uaHash32, String rawUserAgent) {
		String prefix = String.format("UA:%08x ", uaHash32);
		String ua = rawUserAgent != null ? rawUserAgent.trim().replaceAll("\\s+", " ") : "";
		if (ua.isEmpty() || "<EMPTY>".equalsIgnoreCase(ua)) {
			ua = "[Empty / Missing User-Agent]";
		}
		int maxUaLen = 60 - prefix.length();
		if (ua.length() > maxUaLen && maxUaLen > 3) {
			ua = ua.substring(0, maxUaLen - 3) + "...";
		} else if (ua.length() > maxUaLen) {
			ua = "";
		}
		return (prefix + ua).trim();
	}

	public UaPreflightCheckResult evaluateUaPreflight(String rawUserAgent) {
		String trimmed = rawUserAgent != null ? rawUserAgent.trim() : "";
		List<PreflightWarning> warnings = new ArrayList<>();
		if ("-".equals(trimmed)) {
			warnings.add(new PreflightWarning("WARNING", "-",
					"Dash '-' detected as User-Agent string. If this is a placeholder for empty/missing User-Agent from access logs, use '<EMPTY>' or leave input blank."));
		}

		boolean isEmptyUa = trimmed.isEmpty() || "<EMPTY>".equalsIgnoreCase(trimmed) || "-".equals(trimmed);
		String effectiveRaw = isEmptyUa ? "" : trimmed;

		String sha256 = UserAgentMemoryRepository.computeSha256Hex(effectiveRaw);
		int uaHash32 = isEmptyUa ? 0 : UserAgentMemoryRepository.computeUaHash32(effectiveRaw);
		UserAgentFamily classifiedFamily = isEmptyUa ? UserAgentFamily.EMPTY : UserAgentClassifier.classify(effectiveRaw);
		String browserFamily = classifiedFamily != null ? classifiedFamily.name() : "OTHER";

		String targetLabel = formatUaAuditTarget(uaHash32, effectiveRaw);
		boolean alreadyBlocked = uaRuleRepository != null
				&& uaRuleRepository.findByHashAndScope(sha256, "ALL")
						.map(r -> r.isCurrentlyActive(Instant.now()))
						.orElse(false);
		if (alreadyBlocked) {
			warnings.add(new PreflightWarning("WARNING", targetLabel,
					"An active dynamic User-Agent rule already exists for this signature. Submitting will extend/update it."));
		}

		if (isEmptyUa) {
			warnings.add(new PreflightWarning("WARNING", targetLabel,
					"Missing/Empty User-Agent header (0x00000000 / UA:0). Legitimate automated tools, internal APIs, or CLI clients might omit User-Agent headers. Authenticated users and private subnet IPs will bypass this rule if configured."));
		}

		long obsReqs24h = 0L;
		long authReqs24h = 0L;
		int authSamples24h = 0;
		String autoVerdictName = UserAgentAutoVerdict.NEUTRAL.name();
		String manualOverrideName = UserAgentManualOverride.AUTO.name();

		Optional<UserAgentProfile> profileOpt = Optional.empty();
		if (uaMemoryRepository != null) {
			profileOpt = uaMemoryRepository.findByRawUserAgent(effectiveRaw);
		}
		if (profileOpt.isPresent()) {
			UserAgentProfile p = profileOpt.get();
			browserFamily = p.browserFamily() != null ? p.browserFamily().name() : browserFamily;
			obsReqs24h = p.last24hRequests();
			authReqs24h = p.last24hAuthRequests();
			authSamples24h = p.last24hAuthSamples();
			UserAgentAutoVerdict autoVerdict = p.effectiveAutoVerdict();
			UserAgentManualOverride manualOverride = p.effectiveOverride();
			autoVerdictName = autoVerdict.name();
			manualOverrideName = manualOverride.name();

			if (manualOverride == UserAgentManualOverride.ALWAYS_ALLOW) {
				warnings.add(new PreflightWarning("CRITICAL", targetLabel,
						"Protected Override: This User-Agent is marked ALWAYS_ALLOW in UA Memory (" +
								(p.operatorNote() != null && !p.operatorNote().isBlank() ? p.operatorNote() : "explicit admin allowlist") + ")."));
			} else if (manualOverride == UserAgentManualOverride.OBSERVE_ONLY) {
				warnings.add(new PreflightWarning("WARNING", targetLabel,
						"Watchlist Override: This User-Agent is currently set to OBSERVE_ONLY in UA Memory."));
			}

			if (autoVerdict.isImmune()) {
				warnings.add(new PreflightWarning("CRITICAL", targetLabel,
						"Stage-0 Immunity Barrier: Classified as " + autoVerdict.displayName()
								+ " (internal network, verified search engine, or authenticated traffic)."));
			}

			if (authReqs24h > 0 || authSamples24h > 0 || p.totalAuthenticatedRequests() > 0) {
				// Valve bypasses dynamic UA rules for authenticated requests and clean returning visitors,
				// so shared-subnet auth hits are informational rather than a blocking error.
				warnings.add(new PreflightWarning("WARNING", targetLabel,
						"Observed authenticated usage in associated slots (24h slot auth reqs: " + authReqs24h
								+ ", 24h auth samples: " + authSamples24h
								+ ", lifetime auth reqs: " + p.totalAuthenticatedRequests() + ")."));
			}

			if (p.last24hInternalRequests() > 0) {
				warnings.add(new PreflightWarning("WARNING", targetLabel,
						"Internal / campus origin traffic detected (" + p.last24hInternalRequests() + " requests in 24h)."));
			}
		} else {
			warnings.add(new PreflightWarning("INFO", targetLabel,
					"No 24h profile found in UA Memory yet. 32-bit FNV-1a hash is " + String.format("0x%08x", uaHash32) + "."));
		}

		boolean safe = warnings.stream().noneMatch(w -> "CRITICAL".equalsIgnoreCase(w.severity()));
		return new UaPreflightCheckResult(effectiveRaw, sha256, uaHash32, browserFamily, true, alreadyBlocked,
				warnings, obsReqs24h, authReqs24h, authSamples24h, autoVerdictName, manualOverrideName, safe);
	}

	public MitigationUaRule createOrUpdateUaBlock(
			String rawUserAgent,
			int ttlMinutes,
			String reason,
			String source,
			String batchId,
			boolean confirmOverride,
			String actor) {
		requireWriteMode("Creating or updating dynamic User-Agent blocks");
		if (uaRuleRepository == null) {
			throw new IllegalStateException("MitigationUaRuleRepository is not configured.");
		}
		UaPreflightCheckResult preflight = evaluateUaPreflight(rawUserAgent);
		if (!preflight.valid()) {
			throw new IllegalArgumentException("Invalid User-Agent header: must be non-empty.");
		}
		if (preflight.hasCriticalWarnings() && !confirmOverride) {
			throw new IllegalStateException("Pre-flight check reported critical safety warnings for this User-Agent. Confirm override to proceed.");
		}

		List<MonitoredValve> valves = getMitigationCapableValves();
		int maxTtlSec = computeMaxTtlSeconds(valves);
		int effectiveTtlMin = ttlMinutes > 0 ? ttlMinutes : properties.getDefaultMitigationTtlMinutes();
		if ((long) effectiveTtlMin * 60L > maxTtlSec) {
			effectiveTtlMin = Math.max(1, maxTtlSec / 60);
		}
		Instant now = Instant.now();
		Instant expiresAt = now.plus(Duration.ofMinutes(effectiveTtlMin));

		Optional<MitigationUaRule> existingOpt = uaRuleRepository.findByHashAndScope(preflight.userAgentHash(), "ALL");
		boolean continuesActive = existingOpt.isPresent() && existingOpt.get().isCurrentlyActive(now);
		Optional<MitigationUaRule> carried = continuesActive ? existingOpt : Optional.empty();

		String safeReason = (reason != null && !reason.isBlank()) ? reason.trim() : "Dynamic User-Agent mitigation";
		String safeSource = (source != null && !source.isBlank()) ? source.trim() : MitigationUaRule.SOURCE_MANUAL;

		MitigationUaRule rule = new MitigationUaRule(
				existingOpt.map(MitigationUaRule::id).orElse(null),
				preflight.userAgentHash(),
				preflight.uaHash32(),
				preflight.rawUserAgent(),
				preflight.browserFamily(),
				"ALL",
				MitigationUaRule.STATUS_ACTIVE,
				safeSource,
				batchId,
				safeReason,
				carried.map(MitigationUaRule::createdAt).orElse(now),
				now,
				expiresAt,
				null,
				null,
				carried.map(MitigationUaRule::totalBlockedHits).orElse(0L),
				carried.map(MitigationUaRule::totalBypassedHits).orElse(0L),
				carried.map(MitigationUaRule::lastHitAt).orElse(null)
		);
		MitigationUaRule saved = uaRuleRepository.upsertRule(rule);

		String auditAction = MitigationUaRule.SOURCE_AUTO_UA.equalsIgnoreCase(safeSource)
				? (continuesActive ? "UA_AUTO_EXTEND" : "UA_AUTO_BLOCK")
				: (continuesActive ? "UA_EXTEND" : "UA_BLOCK");
		recordUaAudit(
				saved.id(),
				formatUaAuditTarget(saved.uaHash32(), saved.rawUserAgent()),
				batchId,
				auditAction,
				effectiveTtlMin * 60,
				safeReason + " | UA=" + saved.rawUserAgent(),
				actor != null ? actor : "ADMIN"
		);
		syncFleetMitigations();
		return saved;
	}

	public Optional<MitigationUaRule> extendUaBlock(long ruleId, int additionalMinutes, String actor) {
		requireWriteMode("Extending dynamic User-Agent blocks");
		if (uaRuleRepository == null) {
			return Optional.empty();
		}
		Optional<MitigationUaRule> opt = uaRuleRepository.findById(ruleId);
		if (opt.isEmpty()) {
			return Optional.empty();
		}
		MitigationUaRule existing = opt.get();
		int addMin = additionalMinutes > 0 ? additionalMinutes : properties.getDefaultMitigationTtlMinutes();
		int maxTtlSec = getEffectiveMaxTtlSeconds();
		Instant now = Instant.now();
		Instant base = (existing.expiresAt() != null && existing.expiresAt().isAfter(now)
				&& MitigationUaRule.STATUS_ACTIVE.equals(existing.status()))
				? existing.expiresAt() : now;
		Instant newExpiresAt = base.plus(Duration.ofMinutes(addMin));
		Instant maxAllowedExpiry = now.plus(Duration.ofSeconds(Math.max(60, maxTtlSec)));
		if (newExpiresAt.isAfter(maxAllowedExpiry)) {
			newExpiresAt = maxAllowedExpiry;
		}

		MitigationUaRule updated = new MitigationUaRule(
				existing.id(),
				existing.userAgentHash(),
				existing.uaHash32(),
				existing.rawUserAgent(),
				existing.browserFamily(),
				existing.targetScope(),
				MitigationUaRule.STATUS_ACTIVE,
				existing.source(),
				existing.batchId(),
				existing.reason(),
				existing.createdAt(),
				now,
				newExpiresAt,
				null,
				null,
				existing.totalBlockedHits(),
				existing.totalBypassedHits(),
				existing.lastHitAt()
		);
		MitigationUaRule saved = uaRuleRepository.upsertRule(updated);
		recordUaAudit(
				saved.id(),
				formatUaAuditTarget(saved.uaHash32(), saved.rawUserAgent()),
				saved.batchId(),
				"UA_EXTEND",
				(int) Math.max(0L, Duration.between(now, newExpiresAt).toSeconds()),
				"Extended by +" + addMin + " min | UA=" + saved.rawUserAgent(),
				actor != null ? actor : "ADMIN"
		);
		syncFleetMitigations();
		return Optional.of(saved);
	}

	public Optional<MitigationUaRule> revokeUaBlock(long ruleId, String revokeReason, String actor) {
		requireWriteMode("Revoking dynamic User-Agent blocks");
		if (uaRuleRepository == null) {
			return Optional.empty();
		}
		Optional<MitigationUaRule> opt = uaRuleRepository.findById(ruleId);
		if (opt.isEmpty()) {
			return Optional.empty();
		}
		MitigationUaRule existing = opt.get();
		Instant now = Instant.now();
		String safeRevokeReason = (revokeReason != null && !revokeReason.isBlank())
				? revokeReason.trim() : "Manually revoked by operator";

		MitigationUaRule updated = new MitigationUaRule(
				existing.id(),
				existing.userAgentHash(),
				existing.uaHash32(),
				existing.rawUserAgent(),
				existing.browserFamily(),
				existing.targetScope(),
				MitigationUaRule.STATUS_REVOKED,
				existing.source(),
				existing.batchId(),
				existing.reason(),
				existing.createdAt(),
				now,
				now,
				now,
				safeRevokeReason,
				existing.totalBlockedHits(),
				existing.totalBypassedHits(),
				existing.lastHitAt()
		);
		MitigationUaRule saved = uaRuleRepository.upsertRule(updated);
		recordUaAudit(
				saved.id(),
				formatUaAuditTarget(saved.uaHash32(), saved.rawUserAgent()),
				saved.batchId(),
				"UA_REVOKE",
				0,
				safeRevokeReason + " | UA=" + saved.rawUserAgent(),
				actor != null ? actor : "ADMIN"
		);
		syncFleetMitigations();
		return Optional.of(saved);
	}

	public int revokeAllUaBlocks(String revokeReason, String actor) {
		requireWriteMode("Emergency flush of User-Agent blocks");
		if (uaRuleRepository == null) {
			return 0;
		}
		Instant now = Instant.now();
		String safeReason = (revokeReason != null && !revokeReason.isBlank())
				? revokeReason.trim() : "Emergency flush of all dynamic User-Agent rules";
		int count = uaRuleRepository.revokeAllActive(now, safeReason);
		recordUaAudit(null, "ALL_UA_RULES", null, "UA_FLUSH", 0,
				safeReason + " (" + count + " rule(s) revoked)", actor != null ? actor : "ADMIN");
		syncFleetMitigations();
		return count;
	}

	public Optional<MitigationUaRule> getUaRuleById(long ruleId) {
		return uaRuleRepository != null ? uaRuleRepository.findById(ruleId) : Optional.empty();
	}

	public List<MitigationUaRule> getHistoricalUaRulesFiltered(String search, String status, int offset, int limit) {
		return uaRuleRepository != null
				? uaRuleRepository.findHistoricalRulesFiltered(search, status, offset, limit)
				: List.of();
	}

	public long countHistoricalUaRulesFiltered(String search, String status) {
		return uaRuleRepository != null
				? uaRuleRepository.countHistoricalRulesFiltered(search, status)
				: 0L;
	}

	public List<UserAgentProfile> getUaCandidateProfiles(int limit) {
		if (uaMemoryRepository == null) {
			return List.of();
		}
		List<UserAgentProfile> all = uaMemoryRepository.findAllProfiles(Math.max(limit * 4, 200));
		List<UserAgentProfile> candidates = new ArrayList<>();
		for (UserAgentProfile p : all) {
			if (p.isEffectiveProtected()) {
				continue;
			}
			if (p.isEffectiveSuspicious() || p.effectiveOverride() == UserAgentManualOverride.MANUAL_BLOCK) {
				candidates.add(p);
				if (candidates.size() >= limit) {
					break;
				}
			}
		}
		return candidates;
	}

	public EffectiveUaAutoSettings getEffectiveUaAutoSettings() {
		if (settingsRepository == null) {
			return new EffectiveUaAutoSettings(
					false, true, 120, 100, 500L, true, true, true, true, false, false);
		}
		Optional<Boolean> dbEnabled = settingsRepository.getBoolean(KEY_UA_AUTO_ENABLED);
		Optional<Boolean> dbDryRun = settingsRepository.getBoolean(KEY_UA_AUTO_DRY_RUN);
		Optional<Integer> dbTtl = settingsRepository.getInt(KEY_UA_AUTO_DEFAULT_TTL_MINUTES);
		Optional<Integer> dbMaxRules = settingsRepository.getInt(KEY_UA_AUTO_MAX_ACTIVE_RULES);
		Optional<Long> dbMinReqs = settingsRepository.getLong(KEY_UA_AUTO_MIN_REQUESTS_24H);
		Optional<Boolean> dbManual = settingsRepository.getBoolean(KEY_UA_AUTO_BLOCK_MANUAL_CANDIDATES);
		Optional<Boolean> dbP1 = settingsRepository.getBoolean(KEY_UA_AUTO_BLOCK_PILLAR1_SPREAD);
		Optional<Boolean> dbP2 = settingsRepository.getBoolean(KEY_UA_AUTO_BLOCK_PILLAR2_CORRELATED);
		Optional<Boolean> dbP3 = settingsRepository.getBoolean(KEY_UA_AUTO_BLOCK_PILLAR3_DATACENTER);
		Optional<Boolean> dbSig = settingsRepository.getBoolean(KEY_UA_AUTO_BLOCK_SIGNATURE_ANOMALIES);

		boolean hasDbOverrides = dbEnabled.isPresent() || dbDryRun.isPresent() || dbTtl.isPresent()
				|| dbMaxRules.isPresent() || dbMinReqs.isPresent() || dbManual.isPresent()
				|| dbP1.isPresent() || dbP2.isPresent() || dbP3.isPresent() || dbSig.isPresent();

		return new EffectiveUaAutoSettings(
				dbEnabled.orElse(false),
				dbDryRun.orElse(true),
				dbTtl.orElse(120),
				dbMaxRules.orElse(100),
				dbMinReqs.orElse(500L),
				dbManual.orElse(true),
				dbP1.orElse(true),
				dbP2.orElse(true),
				dbP3.orElse(true),
				dbSig.orElse(false),
				hasDbOverrides
		);
	}

	public void updateUaAutoSettings(
			boolean enabled,
			boolean dryRun,
			int defaultTtlMinutes,
			int maxActiveRules,
			long minRequests24h,
			boolean blockManualCandidates,
			boolean blockPillar1Spread,
			boolean blockPillar2Correlated,
			boolean blockPillar3Datacenter,
			boolean blockSignatureAnomalies,
			String updatedBy) {
		if (!properties.getMode().isBackgroundProcessingEnabled()) {
			throw new IllegalStateException("Autonomous User-Agent mitigation settings cannot be modified in " + properties.getMode() + " mode.");
		}
		if (settingsRepository == null) {
			throw new IllegalStateException("SystemSettingsRepository is not configured.");
		}
		String actor = updatedBy != null ? updatedBy : "ADMIN";
		settingsRepository.setSetting(KEY_UA_AUTO_ENABLED, String.valueOf(enabled), "Autonomous UA defense master switch", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_DRY_RUN, String.valueOf(dryRun), "Autonomous UA defense dry-run simulation mode", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_DEFAULT_TTL_MINUTES, String.valueOf(Math.max(1, defaultTtlMinutes)), "Default TTL minutes for auto UA blocks", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_MAX_ACTIVE_RULES, String.valueOf(Math.max(1, maxActiveRules)), "Circuit-breaker max active UA block rules", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_MIN_REQUESTS_24H, String.valueOf(Math.max(1L, minRequests24h)), "Minimum 24h request volume for automatic UA enforcement", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_BLOCK_MANUAL_CANDIDATES, String.valueOf(blockManualCandidates), "Enforce MANUAL_BLOCK User-Agent profiles", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_BLOCK_PILLAR1_SPREAD, String.valueOf(blockPillar1Spread), "Enforce Pillar 1 Ultra-Spread Botnet verdicts", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_BLOCK_PILLAR2_CORRELATED, String.valueOf(blockPillar2Correlated), "Enforce Pillar 2 Correlated Attack verdicts", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_BLOCK_PILLAR3_DATACENTER, String.valueOf(blockPillar3Datacenter), "Enforce Pillar 3 Datacenter Scraper verdicts", actor);
		settingsRepository.setSetting(KEY_UA_AUTO_BLOCK_SIGNATURE_ANOMALIES, String.valueOf(blockSignatureAnomalies), "Enforce Signature / Forged Build anomaly verdicts", actor);
		log.info("Autonomous UA defense settings updated by '{}': enabled={}, dryRun={}, ttlMin={}, maxRules={}, minReq24h={}",
				actor, enabled, dryRun, defaultTtlMinutes, maxActiveRules, minRequests24h);
	}

	public void resetUaAutoSettingsToDefaults(String updatedBy) {
		if (!properties.getMode().isBackgroundProcessingEnabled()) {
			throw new IllegalStateException("Autonomous User-Agent mitigation settings cannot be reset in " + properties.getMode() + " mode.");
		}
		if (settingsRepository == null) {
			return;
		}
		settingsRepository.deleteSetting(KEY_UA_AUTO_ENABLED);
		settingsRepository.deleteSetting(KEY_UA_AUTO_DRY_RUN);
		settingsRepository.deleteSetting(KEY_UA_AUTO_DEFAULT_TTL_MINUTES);
		settingsRepository.deleteSetting(KEY_UA_AUTO_MAX_ACTIVE_RULES);
		settingsRepository.deleteSetting(KEY_UA_AUTO_MIN_REQUESTS_24H);
		settingsRepository.deleteSetting(KEY_UA_AUTO_BLOCK_MANUAL_CANDIDATES);
		settingsRepository.deleteSetting(KEY_UA_AUTO_BLOCK_PILLAR1_SPREAD);
		settingsRepository.deleteSetting(KEY_UA_AUTO_BLOCK_PILLAR2_CORRELATED);
		settingsRepository.deleteSetting(KEY_UA_AUTO_BLOCK_PILLAR3_DATACENTER);
		settingsRepository.deleteSetting(KEY_UA_AUTO_BLOCK_SIGNATURE_ANOMALIES);
		log.info("Autonomous UA defense settings reset to defaults by '{}'", updatedBy);
	}

	public void evaluateAutoUaMitigationIfEnabled() {
		if (!properties.getMode().isBackgroundProcessingEnabled()
				|| uaRuleRepository == null || uaMemoryRepository == null) {
			return;
		}
		EffectiveUaAutoSettings config = getEffectiveUaAutoSettings();
		if (!config.enabled()) {
			return;
		}
		evaluateAutoUaMitigation(config, "AUTO_UA_ENGINE");
	}

	public AutoUaEvaluationResult evaluateAutoUaMitigation(String actor) {
		if (!properties.getMode().isBackgroundProcessingEnabled()) {
			throw new IllegalStateException("Autonomous User-Agent mitigation evaluation is disabled in " + properties.getMode() + " mode.");
		}
		return evaluateAutoUaMitigation(getEffectiveUaAutoSettings(), actor);
	}

	AutoUaEvaluationResult evaluateAutoUaMitigation(EffectiveUaAutoSettings config, String actor) {
		if (uaRuleRepository == null || uaMemoryRepository == null) {
			return new AutoUaEvaluationResult(0, 0, 0, 0);
		}
		String effectiveActor = (actor != null && !actor.isBlank()) ? actor : "AUTO_UA_ENGINE";
		return callWithDeferredFleetSync(() -> {
			Instant now = Instant.now();
			uaRuleRepository.expireElapsedRules(now);
			List<MitigationUaRule> currentlyActive = uaRuleRepository.findActiveRules(now);
			Set<String> activeHashes = new HashSet<>();
			Map<String, MitigationUaRule> activeRulesByHash = new HashMap<>();
			for (MitigationUaRule r : currentlyActive) {
				activeHashes.add(r.userAgentHash());
				activeRulesByHash.put(r.userAgentHash(), r);
			}
			int remainingCapacity = Math.max(0, config.maxActiveRules() - currentlyActive.size());
			long renewalLeadSeconds = Math.min(900L, Math.max(60L, (config.defaultTtlMinutes() * 60L) / 4L));

			List<UserAgentProfile> profiles = new ArrayList<>(uaMemoryRepository.findAllProfiles(500));
			// Ensure manual block candidates outside top-500 volume are also considered
			Map<String, UserAgentProfile> overrides = uaMemoryRepository.findAllManualOverrides();
			Set<String> seenHashes = new HashSet<>();
			for (UserAgentProfile p : profiles) {
				seenHashes.add(p.userAgentHash());
			}
			for (UserAgentProfile op : overrides.values()) {
				if (!seenHashes.contains(op.userAgentHash())) {
					profiles.add(op);
					seenHashes.add(op.userAgentHash());
				}
			}

			int evaluated = 0;
			int activated = 0;
			int dryRunLogged = 0;
			int skippedProtected = 0;

			for (UserAgentProfile p : profiles) {
				if (p.rawUserAgent() == null || p.rawUserAgent().isBlank() || "-".equals(p.rawUserAgent().trim())) {
					continue;
				}
				UserAgentAutoVerdict autoVerdict = p.effectiveAutoVerdict();
				UserAgentManualOverride override = p.effectiveOverride();

				if (override == UserAgentManualOverride.ALWAYS_ALLOW
						|| override == UserAgentManualOverride.OBSERVE_ONLY
						|| (override != UserAgentManualOverride.MANUAL_BLOCK && autoVerdict.isImmune())) {
					if (autoVerdict.isSuspicious()) {
						skippedProtected++;
					}
					continue;
				}

				String matchReason = null;
				if (override == UserAgentManualOverride.MANUAL_BLOCK && config.blockManualCandidates()) {
					matchReason = "Manual block candidate from UA Memory"
							+ (p.operatorNote() != null && !p.operatorNote().isBlank() ? " (" + p.operatorNote() + ")" : "");
				} else if (override == UserAgentManualOverride.AUTO && p.last24hRequests() >= config.minRequests24h()) {
					boolean matchedPillar = switch (autoVerdict) {
						case SUSPICIOUS_ULTRA_SPREAD -> config.blockPillar1Spread();
						case SUSPICIOUS_CORRELATED -> config.blockPillar2Correlated();
						case SUSPICIOUS_DATACENTER -> config.blockPillar3Datacenter();
						case SUSPICIOUS_SIGNATURE -> config.blockSignatureAnomalies();
						default -> false;
					};
					if (matchedPillar) {
						matchReason = autoVerdict.displayName() + " (" + p.last24hRequests() + " req/24h, "
								+ p.last24hDistinctSubnets() + " subnets, " + p.last24hDistinctAsns() + " ASNs)";
					}
				}

				if (matchReason == null) {
					continue;
				}
				evaluated++;
				boolean alreadyActive = activeHashes.contains(p.userAgentHash());
				if (alreadyActive) {
					if (config.dryRun()) {
						continue;
					}
					MitigationUaRule existingRule = activeRulesByHash.get(p.userAgentHash());
					boolean withinRenewalWindow = existingRule != null
							&& existingRule.expiresAt() != null
							&& !existingRule.expiresAt().isAfter(now.plusSeconds(renewalLeadSeconds));
					boolean ongoingTraffic = existingRule != null && (
							(existingRule.lastHitAt() != null
									&& existingRule.lastHitAt().isAfter(now.minusSeconds(Math.max(900L, renewalLeadSeconds))))
							|| (p.lastSeenAt() != null
									&& existingRule.updatedAt() != null
									&& !p.lastSeenAt().isBefore(existingRule.updatedAt())));
					if (!withinRenewalWindow || !ongoingTraffic) {
						continue;
					}
				} else if (config.dryRun()) {
					recordUaAudit(null, formatUaAuditTarget(p.uaHash32(), p.rawUserAgent()),
							"DRY-RUN-UA", "UA_AUTO_WOULD_BLOCK", config.defaultTtlMinutes() * 60,
							"[DRY-RUN] " + matchReason + " | UA=" + p.rawUserAgent(), effectiveActor);
					dryRunLogged++;
					continue;
				} else if (remainingCapacity <= 0) {
					log.info("[AUTO-UA-CAP] Skipping auto UA block for {} because active UA cap ({}) is reached.",
							formatUaAuditTarget(p.uaHash32(), p.rawUserAgent()), config.maxActiveRules());
					continue;
				}
				try {
					MitigationUaRule saved = createOrUpdateUaBlock(p.rawUserAgent(), config.defaultTtlMinutes(), matchReason,
							MitigationUaRule.SOURCE_AUTO_UA, "AUTO-UA", false, effectiveActor);
					activeHashes.add(p.userAgentHash());
					activeRulesByHash.put(p.userAgentHash(), saved);
					if (!alreadyActive) {
						remainingCapacity--;
					}
					activated++;
				} catch (Exception e) {
					log.debug("Skipped auto UA block for {}: {}", formatUaAuditTarget(p.uaHash32(), p.rawUserAgent()), e.getMessage());
					skippedProtected++;
				}
			}

			return new AutoUaEvaluationResult(evaluated, activated, dryRunLogged, skippedProtected);
		});
	}

	public List<MonitoredValve> getMitigationCapableValves() {
		return valveRepository.findAllActive().stream()
				.filter(MonitoredValve::dynamicMitigationEnabled)
				.toList();
	}

	private static Instant toInstant(Object val) {
		if (val == null) {
			return null;
		}
		if (val instanceof Timestamp ts) {
			return ts.toInstant();
		}
		if (val instanceof Instant inst) {
			return inst;
		}
		if (val instanceof Number num) {
			return Instant.ofEpochMilli(num.longValue());
		}
		if (val instanceof String s && !s.isBlank()) {
			try {
				return Instant.parse(s);
			} catch (Exception ignored) {
				try {
					return Timestamp.valueOf(s).toInstant();
				} catch (Exception ignored2) {
				}
			}
		}
		return null;
	}

	private static byte[] parseIPv4Literal(String ip) {
		int len = ip.length();
		if (len < 7 || len > 15) {
			return null;
		}
		int octetCount = 0;
		byte[] bytes = new byte[4];
		int curOctet = 0;
		int digits = 0;
		for (int i = 0; i < len; i++) {
			char c = ip.charAt(i);
			if (c >= '0' && c <= '9') {
				curOctet = curOctet * 10 + (c - '0');
				digits++;
				if (digits > 3 || curOctet > 255) {
					return null;
				}
			} else if (c == '.') {
				if (digits == 0 || octetCount == 3) {
					return null;
				}
				bytes[octetCount++] = (byte) curOctet;
				curOctet = 0;
				digits = 0;
			} else {
				return null;
			}
		}
		if (digits == 0 || octetCount != 3) {
			return null;
		}
		bytes[3] = (byte) curOctet;
		return bytes;
	}

	private static long bytesToLong(byte[] b, int offset) {
		return ((long) (b[offset] & 0xFF) << 56)
				| ((long) (b[offset + 1] & 0xFF) << 48)
				| ((long) (b[offset + 2] & 0xFF) << 40)
				| ((long) (b[offset + 3] & 0xFF) << 32)
				| ((long) (b[offset + 4] & 0xFF) << 24)
				| ((long) (b[offset + 5] & 0xFF) << 16)
				| ((long) (b[offset + 6] & 0xFF) << 8)
				| ((long) (b[offset + 7] & 0xFF));
	}

	private static void longToBytes(long val, byte[] b, int offset) {
		b[offset] = (byte) (val >>> 56);
		b[offset + 1] = (byte) (val >>> 48);
		b[offset + 2] = (byte) (val >>> 40);
		b[offset + 3] = (byte) (val >>> 32);
		b[offset + 4] = (byte) (val >>> 24);
		b[offset + 5] = (byte) (val >>> 16);
		b[offset + 6] = (byte) (val >>> 8);
		b[offset + 7] = (byte) val;
	}
}
