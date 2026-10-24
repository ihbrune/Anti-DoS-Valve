package org.henbru.antidos.collector.enrichment;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EnrichmentStatus;
import org.henbru.antidos.collector.model.IntelRange;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.model.NetworkEntity;
import org.henbru.antidos.collector.storage.NetworkEntityRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Service that resolves clientKeys into normalized NetworkEntity domain records,
 * performs multi-source intelligence correlation (MMDB, Feeds, Tor, Private),
 * maintains an in-memory cache, and manages entity-match persistence.
 */
@Service
public class EntityResolver {

	private static final Logger log = LoggerFactory.getLogger(EntityResolver.class);
	private static final int MAX_CACHE_ENTRIES = 50_000;

	private final NetworkEntityRepository entityRepository;
	private final IntelRegistry intelRegistry;
	private final AsnClassifierService asnClassifierService;
	private final MmdbEnrichmentProvider mmdbProvider;
	private final CollectorProperties properties;
	private final JdbcTemplate jdbcTemplate;

	private final Map<String, NetworkEntity> entityCache = new ConcurrentHashMap<>(16_384);

	@Autowired
	public EntityResolver(
			NetworkEntityRepository entityRepository,
			IntelRegistry intelRegistry,
			AsnClassifierService asnClassifierService,
			MmdbEnrichmentProvider mmdbProvider,
			CollectorProperties properties,
			JdbcTemplate jdbcTemplate) {
		this.entityRepository = entityRepository;
		this.intelRegistry = intelRegistry;
		this.asnClassifierService = asnClassifierService;
		this.mmdbProvider = mmdbProvider;
		this.properties = properties;
		this.jdbcTemplate = jdbcTemplate;
	}

	/**
	 * Returns the cached NetworkEntity if present in memory and not expired, without accessing the database.
	 */
	public Optional<NetworkEntity> getCached(String clientKey) {
		if (clientKey == null || clientKey.trim().isEmpty()) {
			return Optional.empty();
		}
		String cleanKey = clientKey.trim();
		NetworkEntity cached = entityCache.get(cleanKey);
		if (cached != null && !isExpired(cached)) {
			return Optional.of(cached);
		}
		return Optional.empty();
	}

	/**
	 * Looks up the NetworkEntity for the clientKey from cache or database, or registers it if new.
	 */
	public NetworkEntity getOrCreate(String clientKey, Instant seenAt) {
		if (clientKey == null || clientKey.trim().isEmpty()) {
			throw new IllegalArgumentException("clientKey cannot be null or empty");
		}
		String cleanKey = clientKey.trim();

		NetworkEntity cached = entityCache.get(cleanKey);
		if (cached != null) {
			if (isExpired(cached)) {
				entityCache.remove(cleanKey);
				entityRepository.markPending(cached.id());
				cached = cached.withEnrichmentStatus(EnrichmentStatus.PENDING);
			}
			return cached;
		}

		Optional<NetworkEntity> fromDb = entityRepository.findByClientKey(cleanKey);
		if (fromDb.isPresent()) {
			NetworkEntity existing = fromDb.get();
			if (isExpired(existing)) {
				entityRepository.markPending(existing.id());
				existing = existing.withEnrichmentStatus(EnrichmentStatus.PENDING);
			}
			putCache(cleanKey, existing);
			return existing;
		}

		// Create initial pending entity
		IpNetworkInfo net = IpNetworkUtil.parse(cleanKey);
		NetworkEntity pending = NetworkEntity.pending(cleanKey, net, seenAt != null ? seenAt : Instant.now());
		entityRepository.batchUpsert(List.of(pending));

		// Retrieve with assigned database ID
		NetworkEntity created = entityRepository.findByClientKey(cleanKey)
				.orElse(pending);
		putCache(cleanKey, created);
		return created;
	}

	/**
	 * Resolves ASN, geo, and client classifications across all intelligence sources.
	 */
	public NetworkEntity resolve(NetworkEntity entity) {
		if (entity == null || entity.clientKey() == null) {
			return entity;
		}

		String cleanIp = extractCleanIp(entity.clientKey());
		Instant now = Instant.now();

		// 1. Private / Local intranet networks
		if (IpNetworkUtil.isPrivateOrLocal(cleanIp)) {
			String desc = IpNetworkUtil.getPrivateNetworkDescription(cleanIp);
			NetworkEntity enriched = new NetworkEntity(
					entity.id(),
					entity.clientKey(),
					entity.ipVersion(),
					entity.cidrPrefix(),
					entity.ipV4Start(),
					entity.ipV4End(),
					entity.ipV6Start(),
					entity.ipV6End(),
					entity.subnetGroup(),
					null,
					null,
					desc != null ? desc : "Private Network",
					null,
					ClientType.PRIVATE_NETWORK,
					"PRIVATE_NETWORK",
					EnrichmentStatus.ENRICHED,
					now,
					"v1",
					entity.firstSeen(),
					entity.lastSeen()
			);
			persistEnrichment(enriched, List.of());
			return enriched;
		}

		// 2. Query in-memory IntelRegistry (Crawler feeds, Tor exits, etc.)
		IntelRegistry.IntelLookupResult intelResult = intelRegistry.lookup(entity.clientKey());

		// 3. Query MMDB ASN & Geo
		Long asn = null;
		String asOrg = null;
		String countryCode = null;

		if (mmdbProvider != null && mmdbProvider.isAvailable() && properties.getEnrichment().isEnabled()) {
			try {
				InetAddress addr = InetAddress.getByName(cleanIp);
				MmdbEnrichmentProvider.RawGeoAsn raw = mmdbProvider.lookup(addr);
				asn = raw.asn();
				asOrg = raw.asOrg();
				countryCode = raw.countryCode();
			} catch (UnknownHostException e) {
				log.debug("Could not resolve IP for MMDB lookup: {}", cleanIp);
			}
		}

		// 4. Client Classification & Tags
		ClientType clientType;
		List<String> tags = new ArrayList<>();

		if (intelResult.preferredClientType() != null) {
			clientType = intelResult.preferredClientType();
			if ((clientType == ClientType.SEARCH_ENGINE || clientType == ClientType.AI_CRAWLER)
					&& intelResult.primaryLabel() != null && !intelResult.primaryLabel().isBlank()) {
				asOrg = intelResult.primaryLabel();
			} else if (asOrg == null || asOrg.trim().isEmpty()) {
				asOrg = intelResult.primaryLabel();
			}
		} else {
			clientType = asnClassifierService.classify(asn, asOrg);
		}

		if (intelResult.tags() != null && !intelResult.tags().isBlank()) {
			tags.add(intelResult.tags());
		}
		if (clientType == ClientType.DATACENTER && !tags.contains("DATACENTER")) {
			tags.add("DATACENTER");
		} else if (clientType == ClientType.RESIDENTIAL && !tags.contains("RESIDENTIAL")) {
			tags.add("RESIDENTIAL");
		} else if (clientType == ClientType.MOBILE && !tags.contains("MOBILE")) {
			tags.add("MOBILE");
		}

		String tagsStr = tags.isEmpty() ? null : String.join(",", tags);

		NetworkEntity enriched = new NetworkEntity(
				entity.id(),
				entity.clientKey(),
				entity.ipVersion(),
				entity.cidrPrefix(),
				entity.ipV4Start(),
				entity.ipV4End(),
				entity.ipV6Start(),
				entity.ipV6End(),
				entity.subnetGroup(),
				null,
				asn,
				asOrg,
				countryCode,
				clientType,
				tagsStr,
				EnrichmentStatus.ENRICHED,
				now,
				"v1",
				entity.firstSeen(),
				entity.lastSeen()
		);

		persistEnrichment(enriched, intelResult.matches());
		return enriched;
	}

	private void persistEnrichment(NetworkEntity entity, List<IntelRange> matchedRanges) {
		entityRepository.batchUpdateEnrichment(List.of(entity));
		putCache(entity.clientKey(), entity);

		// Record matches in network_entity_match
		if (entity.id() != null && matchedRanges != null && !matchedRanges.isEmpty()) {
			try {
				for (IntelRange r : matchedRanges) {
					if (r.id() != null) {
						jdbcTemplate.update("""
								INSERT INTO network_entity_match (entity_id, range_id, matched_at)
								VALUES (?, ?, ?)
								ON CONFLICT DO NOTHING
								""", entity.id(), r.id(), Timestamp.from(Instant.now()));
					}
				}
			} catch (DataAccessException e) {
				log.debug("Error recording entity matches for entity {}: {}", entity.id(), e.getMessage());
			}
		}
	}

	private void putCache(String key, NetworkEntity entity) {
		if (entityCache.size() > MAX_CACHE_ENTRIES) {
			entityCache.clear();
		}
		entityCache.put(key, entity);
	}

	public void clearCache() {
		entityCache.clear();
	}

	public boolean isExpired(NetworkEntity entity) {
		if (entity == null || entity.enrichmentStatus() != EnrichmentStatus.ENRICHED) {
			return false;
		}
		if (entity.clientType() == ClientType.PRIVATE_NETWORK) {
			return false;
		}
		int ttlDays = properties != null && properties.getEnrichment() != null
				? properties.getEnrichment().getTtlDays() : 30;
		if (ttlDays <= 0) {
			return false;
		}
		if (entity.resolvedAt() == null) {
			return true;
		}
		return entity.resolvedAt().isBefore(Instant.now().minus(ttlDays, java.time.temporal.ChronoUnit.DAYS));
	}

	private static String extractCleanIp(String key) {
		String s = key.trim();
		int slashIdx = s.indexOf('/');
		if (slashIdx >= 0) {
			s = s.substring(0, slashIdx);
		}
		if (s.startsWith("[") && s.endsWith("]")) {
			s = s.substring(1, s.length() - 1);
		}
		return s;
	}

	public int getCacheSize() {
		return entityCache.size();
	}

	public int getMaxCacheEntries() {
		return MAX_CACHE_ENTRIES;
	}
}
