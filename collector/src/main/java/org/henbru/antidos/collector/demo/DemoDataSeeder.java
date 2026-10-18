package org.henbru.antidos.collector.demo;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.henbru.antidos.collector.model.BlockedClientEvent;
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

	private static final String[] ATTACKER_IPS = {
			"45.154.255.12", "185.220.101.5", "194.26.29.110", "91.240.118.77",
			"185.246.221.84", "103.149.28.19", "193.106.191.66", "195.123.245.9",
			"178.62.204.14", "167.99.165.88", "146.190.112.51", "159.65.130.22",
			"89.248.163.74", "194.38.20.141", "45.148.10.66", "193.32.162.201"
	};

	private final SlotSnapshotRepository slotSnapshotRepository;
	private final ClientEventRepository clientEventRepository;
	private final HeartbeatRepository heartbeatRepository;
	private final PollEventLogRepository pollEventLogRepository;

	public DemoDataSeeder(
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			HeartbeatRepository heartbeatRepository,
			PollEventLogRepository pollEventLogRepository) {
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.heartbeatRepository = heartbeatRepository;
		this.pollEventLogRepository = pollEventLogRepository;
	}

	@EventListener(ApplicationReadyEvent.class)
	public void onApplicationReady() {
		seedIfEmpty();
	}

	@org.springframework.transaction.annotation.Transactional
	public synchronized void seedIfEmpty() {
		if (!slotSnapshotRepository.findRecentFleet(1).isEmpty()) {
			log.info("Demo database already contains historical telemetry. Skipping seed.");
			return;
		}

		long start = System.currentTimeMillis();
		log.info("Seeding realistic 7-day telemetry history into isolated demo database...");

		Instant now = Instant.now();
		Random rnd = new Random(42L); // Fixed seed for reproducible demo analytics

		List<SlotSnapshot> snapshots = new ArrayList<>(2500);
		List<BlockedClientEvent> events = new ArrayList<>(1500);

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
			long edgePrimaryReqs = (long) (500 + 800 * diurnal + rnd.nextInt(250));
			int edgePrimaryActive = (int) (180 + 200 * diurnal + rnd.nextInt(50));
			int edgePrimaryBlocked = 0;

			// Occasional crawlers exceeding rate limit
			if (slotKey % 67 == 0) {
				edgePrimaryBlocked = 1;
				events.add(new BlockedClientEvent(
						null, "Demo-Edge-EU", "Primary-Rate-Limiter", slotKey, startTime,
						"198.51.100.42", 142 + rnd.nextInt(30), 0, false, true, endTime
				));
			}
			if (slotKey % 131 == 0) {
				edgePrimaryBlocked++;
				events.add(new BlockedClientEvent(
						null, "Demo-Edge-EU", "Primary-Rate-Limiter", slotKey, startTime,
						"203.0.113.88", 129 + rnd.nextInt(25), 0, false, true, endTime
				));
			}

			snapshots.add(new SlotSnapshot(
					null, "Demo-Edge-EU", "Primary-Rate-Limiter", slotKey,
					startTime, endTime, edgePrimaryReqs, edgePrimaryActive, edgePrimaryBlocked, true, endTime
			));

			long edgeSubnetReqs = (long) (900 + 1100 * diurnal + rnd.nextInt(350));
			int edgeSubnetActive = (int) (120 + 80 * diurnal + rnd.nextInt(30));
			snapshots.add(new SlotSnapshot(
					null, "Demo-Edge-EU", "Subnet-Guard", slotKey,
					startTime, endTime, edgeSubnetReqs, edgeSubnetActive, 0, true, endTime
			));

			// -----------------------------------------------------------------
			// Server 2: Demo-API-Gateway (API-DoS-Shield under attack)
			// -----------------------------------------------------------------
			boolean isAttackWave1 = (hoursAgo >= 12 && hoursAgo <= 15);      // Major DDoS yesterday
			boolean isAttackWave2 = (hoursAgo >= 70 && hoursAgo <= 74);      // Credential stuffing 3 days ago
			boolean isRecentAttack = (hoursAgo <= 1);                         // Active attack ongoing

			long apiReqs;
			int apiActive;
			int apiBlocked;

			if (isAttackWave1) {
				apiReqs = 6500L + rnd.nextInt(3000);
				apiActive = 1100 + rnd.nextInt(300);
				apiBlocked = 12 + rnd.nextInt(4);
				for (int i = 0; i < apiBlocked && i < ATTACKER_IPS.length; i++) {
					events.add(new BlockedClientEvent(
							null, "Demo-API-Gateway", "API-DoS-Shield", slotKey, startTime,
							ATTACKER_IPS[i], 180 + rnd.nextInt(750), 10 + rnd.nextInt(25), true, true, endTime
					));
				}
			} else if (isAttackWave2) {
				apiReqs = 4800L + rnd.nextInt(2200);
				apiActive = 850 + rnd.nextInt(200);
				apiBlocked = 8 + rnd.nextInt(4);
				for (int i = 0; i < apiBlocked && i < ATTACKER_IPS.length; i++) {
					events.add(new BlockedClientEvent(
							null, "Demo-API-Gateway", "API-DoS-Shield", slotKey, startTime,
							ATTACKER_IPS[(i + 4) % ATTACKER_IPS.length], 140 + rnd.nextInt(500), 5 + rnd.nextInt(15), true, true, endTime
					));
				}
			} else if (isRecentAttack) {
				apiReqs = 5200L + rnd.nextInt(2500);
				apiActive = 980 + rnd.nextInt(250);
				apiBlocked = 10 + rnd.nextInt(5);
				for (int i = 0; i < apiBlocked && i < ATTACKER_IPS.length; i++) {
					events.add(new BlockedClientEvent(
							null, "Demo-API-Gateway", "API-DoS-Shield", slotKey, startTime,
							ATTACKER_IPS[i], 150 + rnd.nextInt(600), 8 + rnd.nextInt(20), rnd.nextBoolean(), true, endTime
					));
				}
			} else {
				// Normal baseline traffic
				apiReqs = (long) (1500 + 1200 * diurnal + rnd.nextInt(400));
				apiActive = (int) (350 + 250 * diurnal + rnd.nextInt(80));
				apiBlocked = 0;
			}

			snapshots.add(new SlotSnapshot(
					null, "Demo-API-Gateway", "API-DoS-Shield", slotKey,
					startTime, endTime, apiReqs, apiActive, apiBlocked, true, endTime
			));

			// -----------------------------------------------------------------
			// Server 3: Demo-Staging-Node (Staging-Limiter)
			// -----------------------------------------------------------------
			long stagingReqs = 40L + rnd.nextInt(70);
			int stagingActive = 15 + rnd.nextInt(20);
			snapshots.add(new SlotSnapshot(
					null, "Demo-Staging-Node", "Staging-Limiter", slotKey,
					startTime, endTime, stagingReqs, stagingActive, 0, true, endTime
			));
		}

		// Batch insert historical snapshots and events
		slotSnapshotRepository.batchUpsert(snapshots);
		clientEventRepository.batchUpsert(events);

		// 2. Pre-populate initial Heartbeats
		heartbeatRepository.upsert(new EndpointHeartbeat(
				"Demo-Edge-EU", "http://localhost:8090/mock-valve/edge-eu/antidos-status",
				true, now, now, null, 14L, 2
		));
		heartbeatRepository.upsert(new EndpointHeartbeat(
				"Demo-API-Gateway", "http://localhost:8090/mock-valve/api-gateway/antidos-status",
				true, now, now, null, 18L, 1
		));
		heartbeatRepository.upsert(new EndpointHeartbeat(
				"Demo-Staging-Node", "http://localhost:8090/mock-valve/staging-node/antidos-status",
				true, now, now, null, 24L, 1
		));

		// 3. Pre-populate Poll Event Audit Logs over the last 24h
		List<PollEventLog> logs = new ArrayList<>();
		for (int h = 24; h >= 1; h--) {
			Instant pollTime = now.minus(h, ChronoUnit.HOURS).plus(rnd.nextInt(10), ChronoUnit.MINUTES);

			// Edge EU
			logs.add(new PollEventLog(
					null, "Demo-Edge-EU", "http://localhost:8090/mock-valve/edge-eu/antidos-status",
					pollTime, "SUCCESS", 200, 12L + rnd.nextInt(15), 2, 2, 0,
					"Polled 2 valve(s), 2 slot(s), 0 event(s)", null
			));

			// API Gateway
			boolean underAttack = (h >= 12 && h <= 15) || (h <= 1);
			int evs = underAttack ? (8 + rnd.nextInt(6)) : 0;
			logs.add(new PollEventLog(
					null, "Demo-API-Gateway", "http://localhost:8090/mock-valve/api-gateway/antidos-status",
					pollTime.plusSeconds(3), "SUCCESS", 200, 18L + rnd.nextInt(20), 1, 1, evs,
					"Polled 1 valve(s), 1 slot(s), " + evs + " event(s)", null
			));

			switch (h) {
				case 9 ->
					// Simulated temporary outage
					logs.add(new PollEventLog(
							null, "Demo-Staging-Node", "http://localhost:8090/mock-valve/staging-node/antidos-status",
							pollTime.plusSeconds(5), "ERROR", 503, 42L, 0, 0, 0,
							"Connection failed: HTTP 503 Service Unavailable", "HTTP 503 response from Demo-Staging-Node"
					));
				case 17, 5 ->
					// Simulated slow response warning
					logs.add(new PollEventLog(
							null, "Demo-Staging-Node", "http://localhost:8090/mock-valve/staging-node/antidos-status",
							pollTime.plusSeconds(5), "WARNING", 200, 1140L + rnd.nextInt(80), 1, 1, 0,
							"Slow response: 1140 ms (threshold: 1000 ms)", null
					));
				default ->
					logs.add(new PollEventLog(
							null, "Demo-Staging-Node", "http://localhost:8090/mock-valve/staging-node/antidos-status",
							pollTime.plusSeconds(5), "SUCCESS", 200, 20L + rnd.nextInt(15), 1, 1, 0,
							"Polled 1 valve(s), 1 slot(s), 0 event(s)", null
					));
			}
		}

		pollEventLogRepository.batchInsert(logs);

		long elapsed = System.currentTimeMillis() - start;
		log.info("Historical demo seed complete in {} ms: Ingested {} slot snapshots, {} client block events, and {} poll audit logs.",
				elapsed, snapshots.size(), events.size(), logs.size());
	}
}
