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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.enrichment.EntityResolver;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.model.NetworkEntity;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.notification.AlertNotificationService;
import org.henbru.antidos.collector.poller.ValveStatusClient;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
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
	private static final long DETERRENCE_WINDOW_SECONDS = 600L; // 10 minutes

	private final CollectorProperties properties;
	private final MitigationRuleRepository ruleRepository;
	private final MonitoredValveRepository valveRepository;
	private final ValveStatusClient statusClient;
	private final EntityResolver entityResolver;
	private final AlertNotificationService notificationService;
	private final JdbcTemplate jdbcTemplate;

	private final AtomicBoolean deterrenceRefreshPending = new AtomicBoolean(false);
	private final AtomicBoolean deterrenceWorkerRunning = new AtomicBoolean(false);

	@Autowired
	public MitigationService(
			CollectorProperties properties,
			MitigationRuleRepository ruleRepository,
			MonitoredValveRepository valveRepository,
			ValveStatusClient statusClient,
			@Autowired(required = false) EntityResolver entityResolver,
			@Autowired(required = false) AlertNotificationService notificationService,
			JdbcTemplate jdbcTemplate) {
		this.properties = properties;
		this.ruleRepository = ruleRepository;
		this.valveRepository = valveRepository;
		this.statusClient = statusClient;
		this.entityResolver = entityResolver;
		this.notificationService = notificationService;
		this.jdbcTemplate = jdbcTemplate;
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

	public long getExpectedRevision(Instant now) {
		ruleRepository.expireElapsedRules(now);
		List<MitigationRule> active = ruleRepository.findActiveRules(now);
		if (active.isEmpty()) {
			return 0L;
		}
		List<String> cidrs = active.stream().map(MitigationRule::cidr).toList();
		return computeRevisionForCidrs(cidrs);
	}

	// =========================================================================
	// Fleet Guardrails & Policy Helpers
	// =========================================================================

	/**
	 * @return The strictest (largest prefix number) minimal IPv4 prefix configured across active mitigation Valves
	 */
	public int getEffectiveMinIpv4Prefix() {
		List<MonitoredValve> valves = getMitigationCapableValves();
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
		List<MonitoredValve> valves = getMitigationCapableValves();
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
		List<MonitoredValve> valves = getMitigationCapableValves();
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
		List<MonitoredValve> valves = getMitigationCapableValves();
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

		int minV4 = getEffectiveMinIpv4Prefix();
		int minV6 = getEffectiveMinIpv6Prefix();

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
			int maxCap = getEffectiveMaxActiveBlocks();
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
		NormalizedCidr norm = normalizeAndValidateCidr(rawCidr, getEffectiveMinIpv4Prefix(), getEffectiveMinIpv6Prefix());
		int effectiveTtlMin = ttlMinutes > 0 ? ttlMinutes : properties.getDefaultMitigationTtlMinutes();
		int maxTtlSec = getEffectiveMaxTtlSeconds();
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
				existingOpt.map(MitigationRule::createdAt).orElse(now),
				now,
				expiresAt,
				null,
				null,
				existingOpt.map(MitigationRule::totalBlockedHits).orElse(0L),
				existingOpt.map(MitigationRule::peakDistinctIps).orElse(0),
				existingOpt.map(MitigationRule::lastHitAt).orElse(null),
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
		if (rawCidrs == null || rawCidrs.isEmpty()) {
			return List.of();
		}
		String batchId = (batchIdPrefix != null && !batchIdPrefix.isBlank() ? batchIdPrefix : "BATCH")
				+ "-" + (System.currentTimeMillis() / 1000L);
		int effectiveTtlMin = ttlMinutes > 0 ? ttlMinutes : properties.getDefaultMitigationTtlMinutes();
		List<MitigationRule> created = new ArrayList<>();
		for (String raw : rawCidrs) {
			if (raw == null || raw.isBlank()) {
				continue;
			}
			MitigationRule r = createOrUpdateBlock(raw, effectiveTtlMin, reason, source, batchId, actor);
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
				  AND (client_type IS NULL OR client_type NOT IN ('SEARCH_ENGINE', 'AI_CRAWLER', 'PRIVATE_NETWORK'))
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
		Instant now = Instant.now();
		ruleRepository.expireElapsedRules(now);
		List<MitigationRule> activeRules = ruleRepository.findActiveRules(now);
		String blocksPayload = buildBlocksPayload(activeRules);
		long expectedRevision = computeRevisionForCidrs(activeRules.stream().map(MitigationRule::cidr).toList());

		List<MonitoredValve> mitigationValves = valveRepository.findAllActive().stream()
				.filter(MonitoredValve::dynamicMitigationEnabled)
				.toList();

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
			EndpointConfig ep = endpointsByName.get(valve.serverId());
			if (ep == null) {
				continue;
			}
			try {
				String targetUrl = resolveMitigationUrl(ep, valve.mitigationUri());
				String token = resolveMitigationToken(ep);
				ValveStatusClient.MitigationCommandResponse resp = statusClient.sendMitigationCommand(
						targetUrl,
						token,
						valve.valveName(),
						"replace",
						null,
						null,
						null,
						blocksPayload
				);
				valveRepository.updateDynamicMitigationStats(
						valve.serverId(),
						valve.valveName(),
						true,
						valve.mitigationUri(),
						resp.activeCount(),
						valve.dynamicBlocksBlockedRequests(),
						resp.revision(),
						now
				);
				syncedCount++;
				if (resp.ttlCappedCountOrDefault() > 0) {
					log.info("Valve '{}/{}' capped TTL for {} dynamic block(s) to mitigationMaxTtlSeconds={}s",
							valve.serverId(), valve.valveName(), resp.ttlCappedCountOrDefault(), resp.mitigationMaxTtlSecondsOrDefault());
				}
			} catch (IOException | InterruptedException | RuntimeException e) {
				String err = valve.serverId() + "/" + valve.valveName() + ": " + ValveStatusClient.formatErrorMessage(e);
				log.warn("Failed to sync dynamic mitigations to '{}': {}", valve.serverId() + "/" + valve.valveName(), e.getMessage());
				errors.add(err);
			}
		}

		return new FleetSyncResult(targetCount, syncedCount, activeRules.size(), expectedRevision, errors);
	}

	/**
	 * Called during the poller cycle when a Valve advertises {@code dynamicMitigationEnabled = true}.
	 * Automatically reconciles the Valve's in-memory registry if its {@code dynamicRulesRevision}
	 * differs from the Collector's expected revision (e.g. after a Tomcat restart).
	 */
	public void syncValveIfNeeded(EndpointConfig endpoint, ValveOverviewDto.ValveSummaryDto valveSummary, Instant now) {
		if (endpoint == null || valveSummary == null || !valveSummary.dynamicMitigationEnabledOrDefault()) {
			return;
		}
		long expectedRevision = getExpectedRevision(now);
		long valveRevision = valveSummary.dynamicRulesRevisionOrDefault();
		if (valveRevision == expectedRevision) {
			return;
		}

		List<MitigationRule> activeRules = ruleRepository.findActiveRules(now);
		String blocksPayload = buildBlocksPayload(activeRules);
		String targetUrl = resolveMitigationUrl(endpoint, valveSummary.mitigationUri());
		String token = resolveMitigationToken(endpoint);

		try {
			ValveStatusClient.MitigationCommandResponse resp = statusClient.sendMitigationCommand(
					targetUrl,
					token,
					valveSummary.monitorName(),
					"replace",
					null,
					null,
					null,
					blocksPayload
			);
			valveRepository.updateDynamicMitigationStats(
					endpoint.getName(),
					valveSummary.monitorName(),
					true,
					valveSummary.mitigationUri(),
					resp.activeCount(),
					valveSummary.dynamicBlocksBlockedRequestsOrDefault(),
					resp.revision(),
					now
			);
			log.info("Auto-synchronized {} dynamic CIDR rule(s) to '{}/{}' (revision {} -> {})",
					resp.activeCount(), endpoint.getName(), valveSummary.monitorName(), valveRevision, resp.revision());
			if (resp.ttlCappedCountOrDefault() > 0) {
				log.info("Valve '{}/{}' capped TTL for {} dynamic block(s) to mitigationMaxTtlSeconds={}s",
						endpoint.getName(), valveSummary.monitorName(), resp.ttlCappedCountOrDefault(), resp.mitigationMaxTtlSecondsOrDefault());
			}
		} catch (Exception e) {
			log.warn("Auto-sync of dynamic CIDR rules to '{}/{}' failed: {}",
					endpoint.getName(), valveSummary.monitorName(), ValveStatusClient.formatErrorMessage(e));
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

	private static String buildBlocksPayload(List<MitigationRule> activeRules) {
		if (activeRules == null || activeRules.isEmpty()) {
			return "";
		}
		StringBuilder sb = new StringBuilder(activeRules.size() * 48);
		for (MitigationRule r : activeRules) {
			String cleanReason = r.reason() != null ? r.reason().replace('|', '/').replace('\n', ' ').replace('\r', ' ') : "Dynamic Mitigation";
			sb.append(r.cidr())
					.append('|')
					.append(r.expiresAt().toEpochMilli())
					.append('|')
					.append(cleanReason)
					.append('\n');
		}
		return sb.toString();
	}

	// =========================================================================
	// Attacker Deterrence Tracking & Evaluation
	// =========================================================================

	/**
	 * Signals a non-blocking Virtual Thread to evaluate attacker deterrence metrics
	 * for all active dynamic mitigation rules.
	 */
	public void refreshDeterrenceMetricsAsync() {
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

	public void refreshDeterrenceMetrics() {
		Instant now = Instant.now();
		ruleRepository.expireElapsedRules(now);
		List<MitigationRule> activeRules = ruleRepository.findActiveRules(now);
		if (activeRules.isEmpty()) {
			return;
		}

		Instant recentCutoff = now.minusSeconds(DETERRENCE_WINDOW_SECONDS);

		for (MitigationRule rule : activeRules) {
			try {
				Map<String, Object> stats = jdbcTemplate.queryForMap("""
						SELECT COALESCE(SUM(request_count), 0) AS total_hits,
						       COALESCE(MAX(distinct_clients), 0) AS peak_ips,
						       MAX(last_updated_at) AS last_hit
						FROM client_events
						WHERE client_key = ?
						  AND status = 'BLOCKED'
						  AND slot_time >= ?
						""",
						rule.cidr(),
						Timestamp.from(rule.createdAt().minusSeconds(60)));

				long totalHits = ((Number) stats.get("total_hits")).longValue();
				int peakIps = ((Number) stats.get("peak_ips")).intValue();
				Instant lastHit = toInstant(stats.get("last_hit"));

				long effectiveHits = Math.max(rule.totalBlockedHits(), totalHits);
				int effectivePeakIps = Math.max(rule.peakDistinctIps(), peakIps);
				Instant effectiveLastHit = lastHit != null ? lastHit : rule.lastHitAt();

				String state;
				if (effectiveLastHit != null && effectiveLastHit.isAfter(recentCutoff) && effectiveHits > 0) {
					state = MitigationRule.DETERRENCE_PERSISTENT;
				} else if (rule.createdAt().isBefore(recentCutoff)) {
					state = MitigationRule.DETERRENCE_DETERRED;
				} else {
					state = MitigationRule.DETERRENCE_OBSERVING;
				}

				ruleRepository.updateDeterrenceTelemetry(
						rule.id(),
						effectiveHits,
						effectivePeakIps,
						effectiveLastHit,
						state,
						now
				);
			} catch (Exception e) {
				log.debug("Could not refresh deterrence stats for {}: {}", rule.cidr(), e.getMessage());
			}
		}
	}

	public List<MitigationRule> getActiveRules() {
		Instant now = Instant.now();
		ruleRepository.expireElapsedRules(now);
		return ruleRepository.findActiveRules(now);
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
		return ruleRepository.findAuditEntriesFiltered(search, action, actor, offset, limit);
	}

	public long countAuditEntriesFiltered(String search, String action, String actor) {
		return ruleRepository.countAuditEntriesFiltered(search, action, actor);
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
				null, ruleId, cidr, batchId, action, actor != null ? actor : "AUTO-ENGINE", ttlSeconds, details, Instant.now()
		));
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
