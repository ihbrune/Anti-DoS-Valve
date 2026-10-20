package org.henbru.antidos.collector.enrichment;

import jakarta.annotation.PreDestroy;
import java.net.InetAddress;
import java.util.Optional;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.IpEnrichmentResult;
import org.henbru.antidos.collector.storage.BotIpRangeRepository;
import org.henbru.antidos.collector.storage.BotIpRangeRepository.BotMatch;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

/**
 * Primary implementation of IpEnrichmentService combining MMDB lookups, verified bot detection,
 * and ASN classification.
 */
@Service
@Primary
public class DefaultIpEnrichmentService implements IpEnrichmentService {

	private static final Logger log = LoggerFactory.getLogger(DefaultIpEnrichmentService.class);

	private final CollectorProperties properties;
	private final AsnClassifierService asnClassifierService;
	private final BotIpRangeRepository botIpRangeRepository;
	private MmdbEnrichmentProvider mmdbProvider;

	@org.springframework.beans.factory.annotation.Autowired
	public DefaultIpEnrichmentService(
			CollectorProperties properties,
			AsnClassifierService asnClassifierService,
			BotIpRangeRepository botIpRangeRepository,
			MmdbEnrichmentProvider mmdbProvider) {
		this.properties = properties;
		this.asnClassifierService = asnClassifierService;
		this.botIpRangeRepository = botIpRangeRepository;
		this.mmdbProvider = mmdbProvider;
	}

	public DefaultIpEnrichmentService(
			CollectorProperties properties,
			AsnClassifierService asnClassifierService,
			BotIpRangeRepository botIpRangeRepository) {
		this(properties, asnClassifierService, botIpRangeRepository, null);
		initMmdbProvider();
	}

	public final synchronized void initMmdbProvider() {
		if (this.mmdbProvider != null) {
			this.mmdbProvider.close();
			this.mmdbProvider = null;
		}
		if (properties.getEnrichment().isEnabled()) {
			String asnDb = properties.getEnrichment().getAsnDatabasePath();
			String countryDb = properties.getEnrichment().getCountryDatabasePath();
			this.mmdbProvider = new MmdbEnrichmentProvider(asnDb, countryDb);
		}
	}

	@Override
	public IpEnrichmentResult enrich(String clientKey) {
		if (clientKey == null || clientKey.trim().isEmpty() || !properties.getEnrichment().isEnabled()) {
			return IpEnrichmentResult.UNKNOWN;
		}

		String cleanIp = extractCleanIp(clientKey);

		// 1. Check if private or local intranet IP
		if (IpNetworkUtil.isPrivateOrLocal(cleanIp)) {
			String desc = IpNetworkUtil.getPrivateNetworkDescription(cleanIp);
			return new IpEnrichmentResult(null, desc != null ? desc : "Private Network", null, ClientType.PRIVATE_NETWORK);
		}

		// 2. Check verified bot/crawler IP range table first
		Optional<BotMatch> botMatch = botIpRangeRepository.findBotForIp(cleanIp);

		// 2. Lookup MMDB ASN & Geo
		Long asn = null;
		String asOrg = null;
		String countryCode = null;

		if (mmdbProvider != null && mmdbProvider.isAvailable()) {
			try {
				InetAddress addr = InetAddress.getByName(cleanIp);
				MmdbEnrichmentProvider.RawGeoAsn raw = mmdbProvider.lookup(addr);
				asn = raw.asn();
				asOrg = raw.asOrg();
				countryCode = raw.countryCode();
			} catch (java.net.UnknownHostException | RuntimeException e) {
				log.debug("Could not resolve IP for MMDB lookup: {}", cleanIp);
			}
		}

		// 3. Determine ClientType
		ClientType clientType;
		if (botMatch.isPresent()) {
			BotMatch match = botMatch.get();
			if ("AI_CRAWLER".equalsIgnoreCase(match.category())) {
				clientType = ClientType.AI_CRAWLER;
			} else if ("TOR_EXIT_NODE".equalsIgnoreCase(match.category())) {
				clientType = ClientType.TOR_EXIT_NODE;
			} else {
				clientType = ClientType.SEARCH_ENGINE;
			}
			if (clientType == ClientType.SEARCH_ENGINE || clientType == ClientType.AI_CRAWLER) {
				if (match.botName() != null && !match.botName().isBlank()) {
					asOrg = match.botName();
				}
			} else if (asOrg == null || asOrg.trim().isEmpty()) {
				asOrg = match.botName();
			}
		} else {
			clientType = asnClassifierService.classify(asn, asOrg);
		}

		return new IpEnrichmentResult(asn, asOrg, countryCode, clientType);
	}

	private String extractCleanIp(String key) {
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

	@PreDestroy
	public void close() {
		if (mmdbProvider != null) {
			mmdbProvider.close();
		}
	}
}
