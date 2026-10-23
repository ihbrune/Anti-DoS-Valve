package org.henbru.antidos.collector.demo;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Historical telemetry data seeder for the Anti-DoS Collector Demo Mode (Option E).
 * Pre-populates the isolated demo database with realistic 7-day metrics, attack waves,
 * top offending IP addresses, and operational audit logs upon initial launch.
 */
@Component
@ConditionalOnProperty(name = "collector.demo-mode", havingValue = "true")
public class DemoDataSeeder {

	private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);

	private static final long SLOT_LENGTH_MILLIS = 10_000L; // 10s slot length

	private record DemoIpProfile(
			String ip,
			Long asn,
			String asOrg,
			String country,
			org.henbru.antidos.collector.model.ClientType type
	) {}

	private static final DemoIpProfile[] DEMO_PROFILES = {
			new DemoIpProfile("2a01:4f8:c010:d56::1", 24940L, "Hetzner Online GmbH", "DE", org.henbru.antidos.collector.model.ClientType.DATACENTER),
			new DemoIpProfile("178.62.204.14", 14061L, "DigitalOcean, LLC", "NL", org.henbru.antidos.collector.model.ClientType.DATACENTER),
			new DemoIpProfile("167.99.165.88", 14061L, "DigitalOcean, LLC", "DE", org.henbru.antidos.collector.model.ClientType.DATACENTER),
			new DemoIpProfile("194.26.29.110", 16276L, "OVH SAS", "FR", org.henbru.antidos.collector.model.ClientType.DATACENTER),
			new DemoIpProfile("45.154.255.12", 45102L, "Alibaba Cloud", "SG", org.henbru.antidos.collector.model.ClientType.DATACENTER),
			new DemoIpProfile("185.220.101.5", 208294L, "Zwiebelfreunde (Tor Exit)", "DE", org.henbru.antidos.collector.model.ClientType.DATACENTER),
			new DemoIpProfile("185.246.221.84", 3320L, "Deutsche Telekom AG", "DE", org.henbru.antidos.collector.model.ClientType.RESIDENTIAL),
			new DemoIpProfile("185.246.221.85", 3320L, "Deutsche Telekom AG", "DE", org.henbru.antidos.collector.model.ClientType.RESIDENTIAL),
			new DemoIpProfile("185.246.221.86", 3320L, "Deutsche Telekom AG", "DE", org.henbru.antidos.collector.model.ClientType.RESIDENTIAL),
			new DemoIpProfile("91.240.118.77", 3209L, "Vodafone Deutschland GmbH", "DE", org.henbru.antidos.collector.model.ClientType.RESIDENTIAL),
			new DemoIpProfile("103.149.28.19", 133480L, "VNPT Residential Fiber", "VN", org.henbru.antidos.collector.model.ClientType.RESIDENTIAL),
			new DemoIpProfile("66.249.66.1", 15169L, "Google LLC", "US", org.henbru.antidos.collector.model.ClientType.SEARCH_ENGINE),
			new DemoIpProfile("20.15.240.65", 8075L, "OpenAI / Microsoft", "US", org.henbru.antidos.collector.model.ClientType.AI_CRAWLER),
			new DemoIpProfile("157.55.39.12", 8075L, "Microsoft Corporation", "US", org.henbru.antidos.collector.model.ClientType.SEARCH_ENGINE),
			new DemoIpProfile("10.68.42.15", null, "Private Network (RFC 1918)", null, org.henbru.antidos.collector.model.ClientType.PRIVATE_NETWORK),
			new DemoIpProfile("fd00:10:68::42", null, "Unique Local Address (RFC 4193)", null, org.henbru.antidos.collector.model.ClientType.PRIVATE_NETWORK)
	};

	private final SlotSnapshotRepository slotSnapshotRepository;
	private final ClientEventRepository clientEventRepository;
	private final HeartbeatRepository heartbeatRepository;
	private final PollEventLogRepository pollEventLogRepository;
	private final org.henbru.antidos.collector.storage.CrawlerFeedRepository crawlerFeedRepository;
	private final JdbcTemplate jdbcTemplate;
	private final org.henbru.antidos.collector.config.CollectorProperties properties;

	public DemoDataSeeder(
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			HeartbeatRepository heartbeatRepository,
			PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.storage.CrawlerFeedRepository crawlerFeedRepository,
			JdbcTemplate jdbcTemplate,
			org.henbru.antidos.collector.config.CollectorProperties properties) {
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.heartbeatRepository = heartbeatRepository;
		this.pollEventLogRepository = pollEventLogRepository;
		this.crawlerFeedRepository = crawlerFeedRepository;
		this.jdbcTemplate = jdbcTemplate;
		this.properties = properties;
	}

	@EventListener(ApplicationReadyEvent.class)
	public void onApplicationReady() {
		seedIfEmpty();
	}

	@org.springframework.transaction.annotation.Transactional
	public synchronized void seedIfEmpty() {
		if (!slotSnapshotRepository.findRecentFleet(1).isEmpty()) {
			log.info("Demo database already contains historical telemetry. Updating any legacy un-enriched demo events...");
			enrichLegacyDemoEventsIfAny();
			return;
		}

		long start = System.currentTimeMillis();
		int instanceCount = Math.max(1, Math.min(26, properties.getDemoInstanceCount()));
		log.info("Seeding realistic 7-day telemetry history into isolated demo database (fleet scale: {} instances/type)...", instanceCount);

		Instant now = Instant.now();
		Random rnd = new Random(42L); // Fixed seed for reproducible demo analytics

		List<String> edgeServers;
		List<String> apiServers;
		List<String> stagingServers;

		if (instanceCount == 1) {
			edgeServers = List.of("Demo-Edge-EU");
			apiServers = List.of("Demo-API-Gateway");
			stagingServers = List.of("Demo-Staging-Node");
		} else {
			edgeServers = new ArrayList<>(instanceCount);
			apiServers = new ArrayList<>(instanceCount);
			stagingServers = new ArrayList<>(instanceCount);
			for (int i = 0; i < instanceCount; i++) {
				char letter = (char) ('A' + i);
				edgeServers.add("Demo-Edge-EU " + letter);
				apiServers.add("Demo-API-Gateway " + letter);
				stagingServers.add("Demo-Staging-Node " + letter);
			}
		}

		List<SlotSnapshot> snapshots = new ArrayList<>(2500 * instanceCount);
		List<ClientEvent> events = new ArrayList<>(1500 * instanceCount);

		// 1. Generate Historical Timepoints:
		// - Last 6 hours: high density (every 1 minute)
		// - 6 hours to 7 days: sampled intervals (every 15 minutes)
		List<Instant> timepoints = new ArrayList<>(1000);

		// Older history: 7 days down to 6 hours ago
		Instant cursor = now.minus(7, ChronoUnit.DAYS);
		Instant highDensityThreshold = now.minus(6, ChronoUnit.HOURS);
		while (cursor.isBefore(highDensityThreshold)) {
			timepoints.add(cursor);
			cursor = cursor.plus(15, ChronoUnit.MINUTES);
		}

		// High density recent history: last 6 hours up to 1 minute ago
		cursor = highDensityThreshold;
		Instant endThreshold = now.minus(10, ChronoUnit.SECONDS);
		while (cursor.isBefore(endThreshold)) {
			timepoints.add(cursor);
			cursor = cursor.plus(1, ChronoUnit.MINUTES);
		}

		for (Instant t : timepoints) {
			long slotKey = t.toEpochMilli() / SLOT_LENGTH_MILLIS;
			Instant startTime = Instant.ofEpochMilli(slotKey * SLOT_LENGTH_MILLIS);
			Instant endTime = Instant.ofEpochMilli((slotKey + 1) * SLOT_LENGTH_MILLIS);
			int hourOfDay = t.atZone(ZoneOffset.UTC).getHour();
			double diurnal = 0.5 + 0.5 * Math.sin((hourOfDay - 6) * Math.PI / 12.0);

			long hoursAgo = ChronoUnit.HOURS.between(t, now);

			// -----------------------------------------------------------------
			// Server 1: Demo-Edge-EU (Primary-Rate-Limiter & Subnet-Guard)
			// -----------------------------------------------------------------
			for (int idx = 0; idx < edgeServers.size(); idx++) {
				String edgeServer = edgeServers.get(idx);
				Random sRnd = (idx == 0) ? rnd : new Random((slotKey * 31L) ^ edgeServer.hashCode());

				long edgePrimaryReqs = (long) (500 + 800 * diurnal + sRnd.nextInt(250));
				int edgePrimaryActive = (int) (180 + 200 * diurnal + sRnd.nextInt(50));
				int edgePrimaryBlocked = 0;

				// Occasional crawlers exceeding rate limit
				if ((slotKey + idx * 7) % 67 == 0) {
					edgePrimaryBlocked = 1;
					events.add(createEnrichedEvent(
							edgeServer, "Primary-Rate-Limiter", slotKey, startTime,
							"20.15.240.65", 8075L, "OpenAI / Microsoft", "US", org.henbru.antidos.collector.model.ClientType.AI_CRAWLER,
							142 + sRnd.nextInt(30), 0, false, true, endTime
					));
				}
				if ((slotKey + idx * 11) % 131 == 0) {
					edgePrimaryBlocked++;
					events.add(createEnrichedEvent(
							edgeServer, "Primary-Rate-Limiter", slotKey, startTime,
							"66.249.66.1", 15169L, "Google LLC", "US", org.henbru.antidos.collector.model.ClientType.SEARCH_ENGINE,
							129 + sRnd.nextInt(25), 0, false, true, endTime
					));
				}

				snapshots.add(new SlotSnapshot(
						null, edgeServer, "Primary-Rate-Limiter", slotKey,
						startTime, endTime, edgePrimaryReqs, edgePrimaryActive, edgePrimaryBlocked, true, endTime
				));

				// Server 1 - Valve 2: Subnet-Guard (aggregates IPv4 into /24 subnets)
				long edgeSubnetReqs = (long) (900 + 1100 * diurnal + sRnd.nextInt(350));
				int edgeSubnetActive = (int) (120 + 80 * diurnal + sRnd.nextInt(30));
				int edgeSubnetBlocked = 0;

				if ((slotKey + idx * 5) % 19 == 0) {
					edgeSubnetBlocked++;
					events.add(createEnrichedEvent(
							edgeServer, "Subnet-Guard", slotKey, startTime,
							"45.154.255.0/24", 45102L, "Alibaba Cloud", "SG", org.henbru.antidos.collector.model.ClientType.DATACENTER,
							290 + sRnd.nextInt(120), 0, true, true, endTime
					));
				}
				if ((slotKey + idx * 13) % 43 == 0) {
					edgeSubnetBlocked++;
					events.add(createEnrichedEvent(
							edgeServer, "Subnet-Guard", slotKey, startTime,
							"185.246.221.0/24", 3320L, "Deutsche Telekom AG", "DE", org.henbru.antidos.collector.model.ClientType.RESIDENTIAL,
							260 + sRnd.nextInt(90), 0, true, true, endTime
					));
				}
				if ((slotKey + idx * 17) % 89 == 0) {
					edgeSubnetBlocked++;
					events.add(createEnrichedEvent(
							edgeServer, "Subnet-Guard", slotKey, startTime,
							"10.68.42.0/24", null, "Private Network (RFC 1918)", null, org.henbru.antidos.collector.model.ClientType.PRIVATE_NETWORK,
							310 + sRnd.nextInt(110), 0, true, true, endTime
					));
				}

				snapshots.add(new SlotSnapshot(
						null, edgeServer, "Subnet-Guard", slotKey,
						startTime, endTime, edgeSubnetReqs, edgeSubnetActive, edgeSubnetBlocked, true, endTime
				));

				// Server 1 - Valve 3: IPv6-Rate-Limiter (dedicated IPv6 traffic & crawler mitigation)
				long edgeIpv6Reqs = (long) (400 + 500 * diurnal + sRnd.nextInt(150));
				int edgeIpv6Active = (int) (80 + 60 * diurnal + sRnd.nextInt(20));
				int edgeIpv6Blocked = 0;

				if ((slotKey + idx * 3) % 23 == 0) {
					edgeIpv6Blocked++;
					events.add(createEnrichedEvent(
							edgeServer, "IPv6-Rate-Limiter", slotKey, startTime,
							"2a02:1205:502c:3b00:1c44:98ff:fe22:1011", 3320L, "Deutsche Telekom AG", "DE", org.henbru.antidos.collector.model.ClientType.RESIDENTIAL,
							165 + sRnd.nextInt(40), 0, true, true, endTime
					));
				}
				if ((slotKey + idx * 9) % 47 == 0) {
					// Second rotating client from the exact same residential /64 prefix
					edgeIpv6Blocked++;
					events.add(createEnrichedEvent(
							edgeServer, "IPv6-Rate-Limiter", slotKey, startTime,
							"2a02:1205:502c:3b00:2d55:77aa:1122:3344", 3320L, "Deutsche Telekom AG", "DE", org.henbru.antidos.collector.model.ClientType.RESIDENTIAL,
							152 + sRnd.nextInt(35), 0, true, true, endTime
					));
				}
				if ((slotKey + idx * 19) % 79 == 0) {
					edgeIpv6Blocked++;
					events.add(createEnrichedEvent(
							edgeServer, "IPv6-Rate-Limiter", slotKey, startTime,
							"fd00:10:68::42", null, "Unique Local Address (RFC 4193)", null, org.henbru.antidos.collector.model.ClientType.PRIVATE_NETWORK,
							140 + sRnd.nextInt(30), 0, true, true, endTime
					));
				}

				snapshots.add(new SlotSnapshot(
						null, edgeServer, "IPv6-Rate-Limiter", slotKey,
						startTime, endTime, edgeIpv6Reqs, edgeIpv6Active, edgeIpv6Blocked, true, endTime
				));
			}

			// -----------------------------------------------------------------
			// Server 2: Demo-API-Gateway (API-DoS-Shield under attack)
			// -----------------------------------------------------------------
			boolean isAttackWave1 = (hoursAgo >= 12 && hoursAgo <= 15);      // Major DDoS yesterday
			boolean isAttackWave2 = (hoursAgo >= 70 && hoursAgo <= 74);      // Credential stuffing 3 days ago
			boolean isRecentAttack = (hoursAgo <= 1);                         // Active attack ongoing

			for (int idx = 0; idx < apiServers.size(); idx++) {
				String apiServer = apiServers.get(idx);
				Random aRnd = (idx == 0) ? rnd : new Random((slotKey * 37L) ^ apiServer.hashCode());

				long apiReqs;
				int apiActive;
				int apiBlocked;

				if (isAttackWave1) {
					apiReqs = 6500L + aRnd.nextInt(3000);
					apiActive = 1100 + aRnd.nextInt(300);
					apiBlocked = 12 + aRnd.nextInt(4);
					for (int i = 0; i < apiBlocked && i < DEMO_PROFILES.length; i++) {
						DemoIpProfile p = DEMO_PROFILES[(i + idx) % DEMO_PROFILES.length];
						events.add(createEnrichedEvent(
								apiServer, "API-DoS-Shield", slotKey, startTime,
								p.ip(), p.asn(), p.asOrg(), p.country(), p.type(),
								180 + aRnd.nextInt(750), 10 + aRnd.nextInt(25), true, true, endTime
						));
					}
				} else if (isAttackWave2) {
					apiReqs = 4800L + aRnd.nextInt(2200);
					apiActive = 850 + aRnd.nextInt(200);
					apiBlocked = 8 + aRnd.nextInt(4);
					for (int i = 0; i < apiBlocked && i < DEMO_PROFILES.length; i++) {
						DemoIpProfile p = DEMO_PROFILES[(i + 4 + idx) % DEMO_PROFILES.length];
						events.add(createEnrichedEvent(
								apiServer, "API-DoS-Shield", slotKey, startTime,
								p.ip(), p.asn(), p.asOrg(), p.country(), p.type(),
								140 + aRnd.nextInt(500), 5 + aRnd.nextInt(15), true, true, endTime
						));
					}
				} else if (isRecentAttack) {
					apiReqs = 5200L + aRnd.nextInt(2500);
					apiActive = 980 + aRnd.nextInt(250);
					apiBlocked = 10 + aRnd.nextInt(5);
					for (int i = 0; i < apiBlocked && i < DEMO_PROFILES.length; i++) {
						DemoIpProfile p = DEMO_PROFILES[(i + idx) % DEMO_PROFILES.length];
						events.add(createEnrichedEvent(
								apiServer, "API-DoS-Shield", slotKey, startTime,
								p.ip(), p.asn(), p.asOrg(), p.country(), p.type(),
								150 + aRnd.nextInt(600), 8 + aRnd.nextInt(20), aRnd.nextBoolean(), true, endTime
						));
					}
				} else {
					// Normal baseline traffic
					apiReqs = (long) (1500 + 1200 * diurnal + aRnd.nextInt(400));
					apiActive = (int) (350 + 250 * diurnal + aRnd.nextInt(80));
					apiBlocked = 0;
				}

				snapshots.add(new SlotSnapshot(
						null, apiServer, "API-DoS-Shield", slotKey,
						startTime, endTime, apiReqs, apiActive, apiBlocked, true, endTime
				));
			}

			// -----------------------------------------------------------------
			// Server 3: Demo-Staging-Node (Staging-Limiter)
			// -----------------------------------------------------------------
			for (int idx = 0; idx < stagingServers.size(); idx++) {
				String stagingServer = stagingServers.get(idx);
				Random stRnd = (idx == 0) ? rnd : new Random((slotKey * 41L) ^ stagingServer.hashCode());
				long stagingReqs = 40L + stRnd.nextInt(70);
				int stagingActive = 15 + stRnd.nextInt(20);
				snapshots.add(new SlotSnapshot(
						null, stagingServer, "Staging-Limiter", slotKey,
						startTime, endTime, stagingReqs, stagingActive, 0, true, endTime
				));
			}
		}

		// Batch insert historical snapshots and events
		slotSnapshotRepository.batchUpsert(snapshots);
		clientEventRepository.batchUpsert(events);
		enrichLegacyDemoEventsIfAny();

		// 2. Pre-populate initial Heartbeats
		List<org.henbru.antidos.collector.config.EndpointConfig> demoEndpoints =
				DemoModeService.createDemoEndpoints(8090, instanceCount);
		for (org.henbru.antidos.collector.config.EndpointConfig ep : demoEndpoints) {
			int valves = ep.getValves() != null ? ep.getValves().size() : 1;
			long lat = ep.getName().contains("Edge") ? 14L : (ep.getName().contains("API") ? 18L : 24L);
			heartbeatRepository.upsert(new EndpointHeartbeat(
					ep.getName(), ep.getUrl(), true, now, now, null, lat, valves
			));
		}

		// 3. Pre-populate Poll Event Audit Logs over the last 24h
		List<PollEventLog> logs = new ArrayList<>();
		for (int h = 24; h >= 1; h--) {
			Instant pollTime = now.minus(h, ChronoUnit.HOURS).plus(rnd.nextInt(10), ChronoUnit.MINUTES);
			for (org.henbru.antidos.collector.config.EndpointConfig ep : demoEndpoints) {
				String name = ep.getName();
				String url = ep.getUrl();
				if (name.contains("Edge")) {
					logs.add(new PollEventLog(
							null, name, url,
							pollTime, "SUCCESS", 200, 12L + rnd.nextInt(15), 3, 3, 0,
							"Polled 3 valve(s), 3 slot(s), 0 event(s)", null
					));
				} else if (name.contains("API")) {
					boolean underAttack = (h >= 12 && h <= 15) || (h <= 1);
					int evs = underAttack ? (8 + rnd.nextInt(6)) : 0;
					logs.add(new PollEventLog(
							null, name, url,
							pollTime.plusSeconds(3), "SUCCESS", 200, 18L + rnd.nextInt(20), 1, 1, evs,
							"Polled 1 valve(s), 1 slot(s), " + evs + " event(s)", null
					));
				} else {
					switch (h) {
						case 9 ->
							logs.add(new PollEventLog(
									null, name, url,
									pollTime.plusSeconds(5), "ERROR", 503, 42L, 0, 0, 0,
									"Connection failed: HTTP 503 Service Unavailable", "HTTP 503 response from " + name
							));
						case 17, 5 ->
							logs.add(new PollEventLog(
									null, name, url,
									pollTime.plusSeconds(5), "WARNING", 200, 1140L + rnd.nextInt(80), 1, 1, 0,
									"Slow response: 1140 ms (threshold: 1000 ms)", null
							));
						default ->
							logs.add(new PollEventLog(
									null, name, url,
									pollTime.plusSeconds(5), "SUCCESS", 200, 20L + rnd.nextInt(15), 1, 1, 0,
									"Polled 1 valve(s), 1 slot(s), 0 event(s)", null
							));
					}
				}
			}
		}

		pollEventLogRepository.batchInsert(logs);

		// 4. Pre-populate verified Crawler Feeds
		crawlerFeedRepository.upsert(new org.henbru.antidos.collector.model.CrawlerFeed(
				"googlebot", "Googlebot", "SEARCH_ENGINE",
				"https://developers.google.com/search/apis/ipranges/googlebot.json",
				now.minus(2, ChronoUnit.HOURS), "SUCCESS", 284, null
		));
		crawlerFeedRepository.upsert(new org.henbru.antidos.collector.model.CrawlerFeed(
				"bingbot", "Bingbot", "SEARCH_ENGINE",
				"https://www.bing.com/toolbox/bingbot.json",
				now.minus(3, ChronoUnit.HOURS), "SUCCESS", 312, null
		));
		crawlerFeedRepository.upsert(new org.henbru.antidos.collector.model.CrawlerFeed(
				"openai-gptbot", "OpenAI GPTBot", "AI_CRAWLER",
				"https://openai.com/gptbot.json",
				now.minus(1, ChronoUnit.HOURS), "SUCCESS", 86, null
		));
		crawlerFeedRepository.upsert(new org.henbru.antidos.collector.model.CrawlerFeed(
				"openai-chatgpt-user", "ChatGPT User", "AI_CRAWLER",
				"https://openai.com/chatgpt-user.json",
				now.minus(1, ChronoUnit.HOURS), "SUCCESS", 42, null
		));

		long elapsed = System.currentTimeMillis() - start;
		log.info("Historical demo seed complete in {} ms: Ingested {} slot snapshots, {} client block events, and {} poll audit logs.",
				elapsed, snapshots.size(), events.size(), logs.size());
	}

	private ClientEvent createEnrichedEvent(
			String serverId,
			String valveName,
			long slotKey,
			Instant slotTime,
			String ip,
			Long asn,
			String asOrg,
			String country,
			org.henbru.antidos.collector.model.ClientType type,
			int requestCount,
			int retainedCount,
			boolean locked,
			boolean completed,
			Instant lastUpdatedAt
	) {
		org.henbru.antidos.collector.model.IpNetworkInfo net = org.henbru.antidos.collector.util.IpNetworkUtil.parse(ip);
		return new ClientEvent(
				null, serverId, valveName, slotKey, slotTime,
				ip, net.version(), net.prefix(), net.v4Start(), net.v4End(),
				net.v6Start(), net.v6End(), net.subnetGroup(),
				requestCount, retainedCount, locked,
				locked ? ClientEvent.STATUS_BLOCKED : ClientEvent.STATUS_ACTIVE,
				completed, lastUpdatedAt,
				asn, asOrg, country, type, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED,
				null
		);
	}

	private void enrichLegacyDemoEventsIfAny() {
		try {
			jdbcTemplate.update("""
					UPDATE client_events
					SET asn = 8075, as_org = 'OpenAI / Microsoft', country_code = 'US', client_type = 'AI_CRAWLER', enrichment_status = 'ENRICHED'
					WHERE client_key = '198.51.100.42' OR client_key = '20.15.240.65'
					""");
			jdbcTemplate.update("""
					UPDATE client_events
					SET asn = 15169, as_org = 'Google LLC', country_code = 'US', client_type = 'SEARCH_ENGINE', enrichment_status = 'ENRICHED'
					WHERE client_key = '203.0.113.88' OR client_key = '66.249.66.1'
					""");
			jdbcTemplate.update("""
					UPDATE client_events
					SET asn = 45102, as_org = 'Alibaba Cloud', country_code = 'SG', client_type = 'DATACENTER', enrichment_status = 'ENRICHED'
					WHERE client_key = '198.51.100.0/24' OR client_key = '45.154.255.0/24'
					""");
			jdbcTemplate.update("""
					UPDATE client_events
					SET asn = 3320, as_org = 'Deutsche Telekom AG', country_code = 'DE', client_type = 'RESIDENTIAL', enrichment_status = 'ENRICHED'
					WHERE client_key = '203.0.113.0/24' OR client_key = '185.246.221.0/24'
					   OR client_key = '2a02:1205:502c:3b00:1c44:98ff:fe22:1011'
					   OR client_key = '2a02:1205:502c:3b00:2d55:77aa:1122:3344'
					""");
			jdbcTemplate.update("""
					UPDATE client_events
					SET as_org = 'Private Network (RFC 1918)', client_type = 'PRIVATE_NETWORK', enrichment_status = 'ENRICHED'
					WHERE client_key = '10.68.42.15' OR client_key = '10.68.42.0/24'
					""");
			jdbcTemplate.update("""
					UPDATE client_events
					SET as_org = 'Unique Local Address (RFC 4193)', client_type = 'PRIVATE_NETWORK', enrichment_status = 'ENRICHED'
					WHERE client_key = '2001:db8:85a3::8a2e:370:7334' OR client_key = 'fd00:10:68::42'
					""");
			// Ensure network_entity records exist for all demo events
			jdbcTemplate.update("""
					INSERT INTO network_entity (
					    client_key, ip_version, cidr_prefix,
					    ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end,
					    subnet_group, mmdb_network, asn, as_org, country_code,
					    client_type, tags, enrichment_status, resolved_at, resolved_versions,
					    first_seen, last_seen
					)
					SELECT
					    b.client_key,
					    MAX(b.ip_version),
					    MAX(b.cidr_prefix),
					    MAX(b.ip_v4_start),
					    MAX(b.ip_v4_end),
					    MAX(b.ip_v6_start),
					    MAX(b.ip_v6_end),
					    MAX(b.subnet_group),
					    NULL,
					    MAX(b.asn),
					    MAX(b.as_org),
					    MAX(b.country_code),
					    COALESCE(MAX(b.client_type), 'UNKNOWN'),
					    NULL,
					    COALESCE(MAX(b.enrichment_status), 'PENDING'),
					    CASE WHEN MAX(b.enrichment_status) = 'ENRICHED' THEN MAX(b.last_updated_at) ELSE NULL END,
					    NULL,
					    MIN(b.slot_time),
					    MAX(b.last_updated_at)
					FROM client_events b
					WHERE NOT EXISTS (
					    SELECT 1 FROM network_entity ne WHERE ne.client_key = b.client_key
					)
					GROUP BY b.client_key
					""");
			// Link entity_id
			jdbcTemplate.update("""
					UPDATE client_events
					SET entity_id = (SELECT ne.id FROM network_entity ne WHERE ne.client_key = client_events.client_key)
					WHERE entity_id IS NULL
					""");
		} catch (DataAccessException e) {
			log.warn("Could not backfill legacy demo events: {}", e.getMessage());
		}
	}
}
