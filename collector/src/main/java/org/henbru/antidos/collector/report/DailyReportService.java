package org.henbru.antidos.collector.report;

import java.sql.Timestamp;
import java.text.NumberFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.henbru.antidos.collector.annotation.AnnotationMarkdownService;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.DailyReport;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.DailyReportRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Service for generating, storing, and rendering permanent daily operational summary reports.
 * Normalizes peak request and block rates across varying Valve slot lengths to provide
 * accurate fleet-wide metrics before raw slot data is pruned by nightly retention jobs.
 */
@Service
public class DailyReportService {

	private static final Logger log = LoggerFactory.getLogger(DailyReportService.class);
	private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");
	private static final DateTimeFormatter DATETIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

	private final JdbcTemplate jdbcTemplate;
	private final DailyReportRepository reportRepository;
	private final MonitoredValveRepository valveRepository;
	private final ClientEventRepository clientEventRepository;
	private final AnnotationMarkdownService markdownService;
	private final CollectorProperties properties;

	public DailyReportService(
			JdbcTemplate jdbcTemplate,
			DailyReportRepository reportRepository,
			MonitoredValveRepository valveRepository,
			ClientEventRepository clientEventRepository,
			AnnotationMarkdownService markdownService,
			CollectorProperties properties
	) {
		this.jdbcTemplate = jdbcTemplate;
		this.reportRepository = reportRepository;
		this.valveRepository = valveRepository;
		this.clientEventRepository = clientEventRepository;
		this.markdownService = markdownService;
		this.properties = properties;
	}

	public Optional<DailyReport> getReport(String reportDate) {
		return reportRepository.findByReportDate(reportDate);
	}

	public Optional<DailyReport> getLatestReport() {
		return reportRepository.findLatest();
	}

	public List<DailyReport> getRecentReports(int limit) {
		return reportRepository.findRecent(limit);
	}

	public List<String> getAllReportDates() {
		return reportRepository.findAllReportDates();
	}

	public String renderToHtml(String markdown) {
		return markdownService.renderToHtml(markdown);
	}

	/**
	 * Convenience scheduled runner invoking report generation for yesterday.
	 */
	public DailyReport generateReportForYesterday() {
		LocalDate yesterday = LocalDate.now(ZoneId.systemDefault()).minusDays(1);
		log.info("Generating daily operational report for yesterday ({})", yesterday);
		return generateDailyReport(yesterday);
	}

	/**
	 * Aggregates all slot telemetry, polling logs, and threat events for the specified date,
	 * normalizes peak metrics across valve slot lengths, builds the markdown report, and persists it.
	 */
	public DailyReport generateDailyReport(LocalDate reportDate) {
		long startMs = System.currentTimeMillis();
		ZoneId zone = ZoneId.systemDefault();
		ZonedDateTime startZdt = reportDate.atStartOfDay(zone);
		Instant startInstant = startZdt.toInstant();
		Instant endInstant = startZdt.plusDays(1).toInstant();
		String dateStr = reportDate.toString();

		log.info("Starting daily report aggregation for date {} (range: {} to {})", dateStr, startInstant, endInstant);

		NumberFormat numFmt = NumberFormat.getInstance(Locale.GERMANY);

		// 1. Load active valves configuration for slotLength & threshold context
		Map<String, MonitoredValve> valveConfigMap = new HashMap<>();
		for (MonitoredValve mv : valveRepository.findAll()) {
			valveConfigMap.put(mv.serverId() + "#" + mv.valveName(), mv);
		}

		// 2. Aggregate Slot Snapshots (Fleet Totals)
		long totalRequests = 0;
		long totalBlocked = 0;
		int serverCount = 0;

		try {
			Long reqSum = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(total_requests), 0) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			totalRequests = reqSum != null ? reqSum : 0L;

			Long blockSum = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(blocked_counters), 0) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			totalBlocked = blockSum != null ? blockSum : 0L;

			Integer srvCnt = jdbcTemplate.queryForObject(
					"SELECT COUNT(DISTINCT server_id) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Integer.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			serverCount = srvCnt != null ? srvCnt : 0;
		} catch (Exception e) {
			log.warn("Error querying slot snapshot totals for {}: {}", dateStr, e.getMessage());
		}

		// 3. Per-Valve Summaries & Peak Calculation (Normalized to Requests / Sec)
		record ValveAggregate(
				String serverId,
				String valveName,
				long totalRequests,
				long totalBlocked,
				int slotCount,
				int configuredSlotLength,
				int allowedRequestsPerSlot,
				double peakReqRatePerSec,
				long peakRawRequests,
				long peakReqDurationSec,
				Instant peakReqTime,
				double peakBlockRatePerSec,
				long peakRawBlocked,
				long peakBlockDurationSec,
				Instant peakBlockTime,
				double peakUtilizationPercent
		) {}

		List<ValveAggregate> valveAggregates = new ArrayList<>();
		double fleetPeakReqRate = 0.0;
		double fleetPeakBlockRate = 0.0;
		String peakReqServer = null;
		String peakReqValve = null;
		Instant fleetPeakReqTime = null;
		long fleetPeakReqRaw = 0;
		long fleetPeakReqDuration = 0;

		String peakBlockServer = null;
		String peakBlockValve = null;
		Instant fleetPeakBlockTime = null;
		long fleetPeakBlockRaw = 0;
		long fleetPeakBlockDuration = 0;

		try {
			String valveQuery = """
					SELECT server_id, valve_name,
					       COALESCE(SUM(total_requests), 0) AS req_sum,
					       COALESCE(SUM(blocked_counters), 0) AS block_sum,
					       COUNT(*) AS slot_count
					FROM slot_snapshots
					WHERE start_time >= ? AND start_time < ?
					GROUP BY server_id, valve_name
					ORDER BY server_id, valve_name
					""";

			List<Map<String, Object>> rows = jdbcTemplate.queryForList(
					valveQuery, Timestamp.from(startInstant), Timestamp.from(endInstant));

			for (Map<String, Object> row : rows) {
				String sId = (String) row.get("server_id");
				String vName = (String) row.get("valve_name");
				long vReqSum = ((Number) row.get("req_sum")).longValue();
				long vBlockSum = ((Number) row.get("block_sum")).longValue();
				int slotCount = ((Number) row.get("slot_count")).intValue();

				MonitoredValve cfg = valveConfigMap.get(sId + "#" + vName);
				int slotLen = cfg != null && cfg.slotLength() > 0 ? cfg.slotLength() : 10;
				int allowedPerSlot = cfg != null ? cfg.allowedRequestsPerSlot() : 0;

				// Query candidate peak request slot for this valve
				List<SlotSnapshot> peakReqSlots = jdbcTemplate.query(
						"SELECT * FROM slot_snapshots WHERE server_id = ? AND valve_name = ? AND start_time >= ? AND start_time < ? ORDER BY total_requests DESC LIMIT 1",
						(rs, rowNum) -> new SlotSnapshot(
								rs.getLong("id"), rs.getString("server_id"), rs.getString("valve_name"),
								rs.getLong("slot_key"), rs.getTimestamp("start_time").toInstant(),
								rs.getTimestamp("end_time").toInstant(), rs.getLong("total_requests"),
								rs.getInt("active_counters"), rs.getInt("blocked_counters"),
								rs.getBoolean("is_completed"), rs.getTimestamp("last_polled_at").toInstant()
						), sId, vName, Timestamp.from(startInstant), Timestamp.from(endInstant));

				double peakReqRate = 0.0;
				long peakRawReq = 0;
				long peakReqDuration = slotLen;
				Instant peakReqTime = null;

				if (!peakReqSlots.isEmpty()) {
					SlotSnapshot s = peakReqSlots.getFirst();
					peakRawReq = s.totalRequests();
					long dur = Math.max(1, Duration.between(s.startTime(), s.endTime()).toSeconds());
					peakReqDuration = dur;
					peakReqRate = (double) peakRawReq / dur;
					peakReqTime = s.startTime();

					if (peakReqRate > fleetPeakReqRate) {
						fleetPeakReqRate = peakReqRate;
						peakReqServer = sId;
						peakReqValve = vName;
						fleetPeakReqTime = peakReqTime;
						fleetPeakReqRaw = peakRawReq;
						fleetPeakReqDuration = peakReqDuration;
					}
				}

				// Query candidate peak blocked slot for this valve
				List<SlotSnapshot> peakBlockSlots = jdbcTemplate.query(
						"SELECT * FROM slot_snapshots WHERE server_id = ? AND valve_name = ? AND start_time >= ? AND start_time < ? ORDER BY blocked_counters DESC LIMIT 1",
						(rs, rowNum) -> new SlotSnapshot(
								rs.getLong("id"), rs.getString("server_id"), rs.getString("valve_name"),
								rs.getLong("slot_key"), rs.getTimestamp("start_time").toInstant(),
								rs.getTimestamp("end_time").toInstant(), rs.getLong("total_requests"),
								rs.getInt("active_counters"), rs.getInt("blocked_counters"),
								rs.getBoolean("is_completed"), rs.getTimestamp("last_polled_at").toInstant()
						), sId, vName, Timestamp.from(startInstant), Timestamp.from(endInstant));

				double peakBlockRate = 0.0;
				long peakRawBlk = 0;
				long peakBlkDuration = slotLen;
				Instant peakBlkTime = null;

				if (!peakBlockSlots.isEmpty()) {
					SlotSnapshot s = peakBlockSlots.getFirst();
					peakRawBlk = s.blockedCounters();
					long dur = Math.max(1, Duration.between(s.startTime(), s.endTime()).toSeconds());
					peakBlkDuration = dur;
					peakBlockRate = (double) peakRawBlk / dur;
					peakBlkTime = s.startTime();

					if (peakBlockRate > fleetPeakBlockRate) {
						fleetPeakBlockRate = peakBlockRate;
						peakBlockServer = sId;
						peakBlockValve = vName;
						fleetPeakBlockTime = peakBlkTime;
						fleetPeakBlockRaw = peakRawBlk;
						fleetPeakBlockDuration = peakBlkDuration;
					}
				}

				double peakUtilization = (allowedPerSlot > 0 && peakRawReq > 0)
						? ((double) peakRawReq / allowedPerSlot) * 100.0 : 0.0;

				valveAggregates.add(new ValveAggregate(
						sId, vName, vReqSum, vBlockSum, slotCount, slotLen, allowedPerSlot,
						peakReqRate, peakRawReq, peakReqDuration, peakReqTime,
						peakBlockRate, peakRawBlk, peakBlkDuration, peakBlkTime,
						peakUtilization
				));
			}
		} catch (Exception e) {
			log.warn("Error querying per-valve aggregates for {}: {}", dateStr, e.getMessage());
		}

		// 4. Polling Telemetry & Latency Distribution (from poll_event_log)
		record PollSummary(
				long totalPolls,
				long successPolls,
				long warningPolls,
				long errorPolls,
				long minMs,
				double avgMs,
				long maxMs,
				long bucketLt50,
				long bucket50to200,
				long bucket200to500,
				long bucketGte500
		) {}

		PollSummary pollSummary = new PollSummary(0, 0, 0, 0, 0, 0.0, 0, 0, 0, 0, 0);
		try {
			String pollSql = """
					SELECT COUNT(*) AS total_polls,
					       COALESCE(SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END), 0) AS success_polls,
					       COALESCE(SUM(CASE WHEN status = 'WARNING' THEN 1 ELSE 0 END), 0) AS warning_polls,
					       COALESCE(SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END), 0) AS error_polls,
					       COALESCE(MIN(response_time_ms), 0) AS min_ms,
					       COALESCE(AVG(response_time_ms), 0.0) AS avg_ms,
					       COALESCE(MAX(response_time_ms), 0) AS max_ms,
					       COALESCE(SUM(CASE WHEN response_time_ms < 50 AND status != 'ERROR' THEN 1 ELSE 0 END), 0) AS bucket_lt_50,
					       COALESCE(SUM(CASE WHEN response_time_ms >= 50 AND response_time_ms < 200 AND status != 'ERROR' THEN 1 ELSE 0 END), 0) AS bucket_50_200,
					       COALESCE(SUM(CASE WHEN response_time_ms >= 200 AND response_time_ms < 500 AND status != 'ERROR' THEN 1 ELSE 0 END), 0) AS bucket_200_500,
					       COALESCE(SUM(CASE WHEN response_time_ms >= 500 AND status != 'ERROR' THEN 1 ELSE 0 END), 0) AS bucket_gte_500
					FROM poll_event_log
					WHERE poll_time >= ? AND poll_time < ?
					""";

			List<PollSummary> summaries = jdbcTemplate.query(pollSql, (rs, rowNum) -> new PollSummary(
					rs.getLong("total_polls"),
					rs.getLong("success_polls"),
					rs.getLong("warning_polls"),
					rs.getLong("error_polls"),
					rs.getLong("min_ms"),
					rs.getDouble("avg_ms"),
					rs.getLong("max_ms"),
					rs.getLong("bucket_lt_50"),
					rs.getLong("bucket_50_200"),
					rs.getLong("bucket_200_500"),
					rs.getLong("bucket_gte_500")
			), Timestamp.from(startInstant), Timestamp.from(endInstant));

			if (!summaries.isEmpty()) {
				pollSummary = summaries.getFirst();
			}
		} catch (Exception e) {
			log.warn("Error querying poll telemetry for {}: {}", dateStr, e.getMessage());
		}

		// Per-server polling stats
		record ServerPollStat(String serverId, long totalPolls, long successPolls, long errorPolls, long minMs, double avgMs, long maxMs) {}
		List<ServerPollStat> serverPollStats = new ArrayList<>();
		try {
			String serverPollSql = """
					SELECT server_id,
					       COUNT(*) AS total_polls,
					       COALESCE(SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END), 0) AS success_polls,
					       COALESCE(SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END), 0) AS error_polls,
					       COALESCE(MIN(response_time_ms), 0) AS min_ms,
					       COALESCE(AVG(response_time_ms), 0.0) AS avg_ms,
					       COALESCE(MAX(response_time_ms), 0) AS max_ms
					FROM poll_event_log
					WHERE poll_time >= ? AND poll_time < ?
					GROUP BY server_id
					ORDER BY server_id
					""";

			serverPollStats = jdbcTemplate.query(serverPollSql, (rs, rowNum) -> new ServerPollStat(
					rs.getString("server_id"),
					rs.getLong("total_polls"),
					rs.getLong("success_polls"),
					rs.getLong("error_polls"),
					rs.getLong("min_ms"),
					rs.getDouble("avg_ms"),
					rs.getLong("max_ms")
			), Timestamp.from(startInstant), Timestamp.from(endInstant));
		} catch (Exception e) {
			log.warn("Error querying server poll stats for {}: {}", dateStr, e.getMessage());
		}

		// Outages / Errors
		record OutageLog(String serverId, Instant pollTime, int httpStatusCode, long responseTimeMs, String errorMessage) {}
		List<OutageLog> outages = new ArrayList<>();
		try {
			String outagesSql = """
					SELECT server_id, poll_time, http_status_code, response_time_ms, error_message
					FROM poll_event_log
					WHERE poll_time >= ? AND poll_time < ? AND status = 'ERROR'
					ORDER BY poll_time ASC
					LIMIT 50
					""";

			outages = jdbcTemplate.query(outagesSql, (rs, rowNum) -> new OutageLog(
					rs.getString("server_id"),
					rs.getTimestamp("poll_time").toInstant(),
					rs.getInt("http_status_code"),
					rs.getLong("response_time_ms"),
					rs.getString("error_message")
			), Timestamp.from(startInstant), Timestamp.from(endInstant));
		} catch (Exception e) {
			log.warn("Error querying outages for {}: {}", dateStr, e.getMessage());
		}

		// 5. Threat Highlights (Top Offending IPs and ASNs from client_events)
		int distinctBlockedClients = 0;
		int totalIncidents = 0;
		try {
			Integer dbc = jdbcTemplate.queryForObject(
					"SELECT COUNT(DISTINCT client_key) FROM client_events WHERE status = 'BLOCKED' AND slot_time >= ? AND slot_time < ?",
					Integer.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			distinctBlockedClients = dbc != null ? dbc : 0;

			Integer inc = jdbcTemplate.queryForObject(
					"SELECT COUNT(*) FROM client_events WHERE status = 'BLOCKED' AND slot_time >= ? AND slot_time < ?",
					Integer.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			totalIncidents = inc != null ? inc : 0;
		} catch (Exception e) {
			log.warn("Error querying incident counts for {}: {}", dateStr, e.getMessage());
		}

		List<TopOffenderSummary> topClients = Collections.emptyList();
		List<TopOffenderSummary> topAsns = Collections.emptyList();
		try {
			topClients = clientEventRepository.findTopOffendersFiltered(
					null, null, startInstant, endInstant, null, null, null, null, "BLOCKED", "client_key", 10);
			topAsns = clientEventRepository.findTopOffendersFiltered(
					null, null, startInstant, endInstant, null, null, null, null, "BLOCKED", "ASN", 5);
		} catch (Exception e) {
			log.warn("Error querying top offenders for {}: {}", dateStr, e.getMessage());
		}

		// 6. Overall Status Classification
		String status;
		double blockRateFleet = totalRequests > 0 ? (totalBlocked * 100.0) / totalRequests : 0.0;
		double errorPollRate = pollSummary.totalPolls() > 0 ? (pollSummary.errorPolls() * 100.0) / pollSummary.totalPolls() : 0.0;

		if (!outages.isEmpty() && errorPollRate > 2.0) {
			status = "DEGRADED";
		} else if (totalBlocked > 50 || blockRateFleet > 1.0 || distinctBlockedClients >= 10) {
			status = "ATTACK_MITIGATED";
		} else if (errorPollRate > 0.5) {
			status = "WARNING";
		} else {
			status = "NORMAL";
		}

		// 7. Render Markdown Content
		String markdown = buildMarkdownReport(
				reportDate, status, totalRequests, totalBlocked, blockRateFleet,
				serverCount, distinctBlockedClients, totalIncidents,
				fleetPeakReqRate, fleetPeakReqRaw, fleetPeakReqDuration, peakReqServer, peakReqValve, fleetPeakReqTime,
				fleetPeakBlockRate, fleetPeakBlockRaw, fleetPeakBlockDuration, peakBlockServer, peakBlockValve, fleetPeakBlockTime,
				valveAggregates, pollSummary, serverPollStats, outages, topClients, topAsns, numFmt
		);

		DailyReport report = new DailyReport(
				null,
				dateStr,
				status,
				totalRequests,
				totalBlocked,
				fleetPeakReqRate,
				fleetPeakBlockRate,
				peakReqValve,
				peakReqServer,
				serverCount,
				totalIncidents,
				markdown,
				Instant.now(),
				Instant.now()
		);

		reportRepository.upsert(report);
		long durationMs = System.currentTimeMillis() - startMs;
		log.info("Daily operational report for {} completed in {}ms (Status: {}, TotalReq: {}, Peaks: {} req/s, {} blk/s)",
				dateStr, durationMs, status, totalRequests, String.format(Locale.US, "%.1f", fleetPeakReqRate), String.format(Locale.US, "%.1f", fleetPeakBlockRate));

		return report;
	}

	private String buildMarkdownReport(
			LocalDate date,
			String status,
			long totalRequests,
			long totalBlocked,
			double blockRateFleet,
			int serverCount,
			int distinctBlockedClients,
			int totalIncidents,
			double fleetPeakReqRate,
			long fleetPeakReqRaw,
			long fleetPeakReqDuration,
			String peakReqServer,
			String peakReqValve,
			Instant fleetPeakReqTime,
			double fleetPeakBlockRate,
			long fleetPeakBlockRaw,
			long fleetPeakBlockDuration,
			String peakBlockServer,
			String peakBlockValve,
			Instant fleetPeakBlockTime,
			List<?> rawValveAggregates,
			Object rawPollSummary,
			List<?> rawServerPollStats,
			List<?> rawOutages,
			List<TopOffenderSummary> topClients,
			List<TopOffenderSummary> topAsns,
			NumberFormat numFmt
	) {
		StringBuilder sb = new StringBuilder();

		String statusBadge = switch (status) {
			case "ATTACK_MITIGATED" -> "🔴 **ATTACK DETECTED & MITIGATED** (Abgewehrte DoS-Welle)";
			case "DEGRADED" -> "🟡 **DEGRADED PERFORMANCE** (Erhöhte Latenzen oder Serverausfälle)";
			case "WARNING" -> "🟡 **WARNING** (Sporadische Warnungen oder Timeout-Spitzen)";
			default -> "🟢 **ALL SYSTEMS OPERATIONAL** (Normaler Regelbetrieb)";
		};

		sb.append("# 🛡️ Anti-DoS Fleet Operational Report — ").append(date).append("\n\n");
		sb.append("> **Tages-Status:** ").append(statusBadge).append("  \n");
		sb.append("> **Analyse-Zeitraum:** `").append(date).append(" 00:00:00` bis `").append(date).append(" 23:59:59` (Systemzeit)  \n");
		sb.append("> **Bericht generiert:** `").append(LocalDateTime.now(ZoneId.systemDefault()).format(DATETIME_FORMATTER)).append("`\n\n");

		sb.append("---\n\n");

		// Executive Summary
		sb.append("## 📊 1. Executive Summary (Flotten-Überblick)\n\n");
		sb.append("| Metrik | Tageswert | Erläuterung & Kontext |\n");
		sb.append("| :--- | :--- | :--- |\n");
		sb.append("| **Gesamtanzahl Requests** | **").append(numFmt.format(totalRequests)).append("** | Über alle überwachten Valves und Nodes gezählte Anfragen |\n");
		sb.append("| **Blockierte Requests** | **").append(numFmt.format(totalBlocked)).append("** | Verweigerte Anfragen (HTTP 429) |\n");
		sb.append("| **Flottenweite Block-Quote** | **").append(String.format(Locale.GERMANY, "%.2f%%", blockRateFleet)).append("** | Anteil abgewiesener Anfragen an der Gesamtlast |\n");
		sb.append("| **Aktive Nodes / Valves** | **").append(serverCount).append(" Server / ").append(rawValveAggregates.size()).append(" Valves** | An der Erfassung beteiligte Instanzen |\n");
		sb.append("| **Geblockte Clients** | **").append(numFmt.format(distinctBlockedClients)).append(" eindeutige IPs** | In Einzelsperren oder Subnetzsperren involviert |\n");
		sb.append("| **Block-Vorfälle (Incidents)** | **").append(numFmt.format(totalIncidents)).append("** | Registrierte Blockade-Slots mit Quotenüberschreitung |\n");

		// Peak Request Rate
		sb.append("| **Peak Request-Rate (normalisiert)** | **`")
				.append(String.format(Locale.GERMANY, "%.1f", fleetPeakReqRate)).append(" req/s`** | ");
		if (peakReqServer != null && peakReqValve != null) {
			String timeStr = fleetPeakReqTime != null ? fleetPeakReqTime.atZone(ZoneId.systemDefault()).format(TIME_FORMATTER) : "N/A";
			sb.append(numFmt.format(fleetPeakReqRaw)).append(" Requests in ").append(fleetPeakReqDuration).append("s-Slot auf `")
					.append(peakReqServer).append("` / Valve `").append(peakReqValve).append("` (um ").append(timeStr).append(" Uhr)");
		} else {
			sb.append("Keine Last gemessen");
		}
		sb.append(" |\n");

		// Peak Block Rate
		sb.append("| **Peak Block-Rate (normalisiert)** | **`")
				.append(String.format(Locale.GERMANY, "%.1f", fleetPeakBlockRate)).append(" blocks/s`** | ");
		if (peakBlockServer != null && peakBlockValve != null && fleetPeakBlockRaw > 0) {
			String timeStr = fleetPeakBlockTime != null ? fleetPeakBlockTime.atZone(ZoneId.systemDefault()).format(TIME_FORMATTER) : "N/A";
			sb.append(numFmt.format(fleetPeakBlockRaw)).append(" Blockaden in ").append(fleetPeakBlockDuration).append("s-Slot auf `")
					.append(peakBlockServer).append("` / Valve `").append(peakBlockValve).append("` (um ").append(timeStr).append(" Uhr)");
		} else {
			sb.append("Keine aktiven Blockaden aufgetreten");
		}
		sb.append(" |\n\n");

		sb.append("---\n\n");

		// Server- & Valve-Breakdown
		sb.append("## ⚡ 2. Server- & Valve-Statistiken (mit normalisierten Spitzenwerten)\n\n");
		sb.append("> ℹ️ **Hinweis zur Normalisierung:** Um Valves mit unterschiedlichen Slotlängen (z. B. 5s vs. 60s) objektiv vergleichen zu können, ");
		sb.append("werden die Peak-Werte auf Sekundenraten (`req/s` und `blocks/s`) umgerechnet.\n\n");

		// Group valve aggregates by serverId
		Map<String, List<Object>> serverMap = new LinkedHashMap<>();
		for (Object agg : rawValveAggregates) {
			try {
				java.lang.reflect.Method m = agg.getClass().getMethod("serverId");
				String sId = (String) m.invoke(agg);
				serverMap.computeIfAbsent(sId, k -> new ArrayList<>()).add(agg);
			} catch (Exception ignored) {}
		}

		if (serverMap.isEmpty()) {
			sb.append("*Keine Valve-Telemetriedaten für diesen Tag erfasst.*\n\n");
		} else {
			for (Map.Entry<String, List<Object>> entry : serverMap.entrySet()) {
				String sId = entry.getKey();
				List<Object> valves = entry.getValue();

				sb.append("### Server `").append(sId).append("` (").append(valves.size()).append(" Valves)\n\n");
				sb.append("| Valve | Slotlänge | Gesamt-Requests | Blockaden | Quote | Peak-Rate (norm.) | Peak-Slot (raw) | Peak-Auslastung |\n");
				sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

				for (Object vObj : valves) {
					try {
						String vName = (String) vObj.getClass().getMethod("valveName").invoke(vObj);
						long vReq = (Long) vObj.getClass().getMethod("totalRequests").invoke(vObj);
						long vBlk = (Long) vObj.getClass().getMethod("totalBlocked").invoke(vObj);
						int slotLen = (Integer) vObj.getClass().getMethod("configuredSlotLength").invoke(vObj);
						int allowed = (Integer) vObj.getClass().getMethod("allowedRequestsPerSlot").invoke(vObj);
						double pReqRate = (Double) vObj.getClass().getMethod("peakReqRatePerSec").invoke(vObj);
						long pRawReq = (Long) vObj.getClass().getMethod("peakRawRequests").invoke(vObj);
						long pReqDur = (Long) vObj.getClass().getMethod("peakReqDurationSec").invoke(vObj);
						double pUtil = (Double) vObj.getClass().getMethod("peakUtilizationPercent").invoke(vObj);

						double vQuote = vReq > 0 ? (vBlk * 100.0) / vReq : 0.0;
						String utilStr = allowed > 0 ? String.format(Locale.GERMANY, "%.1f%% (%s max)", pUtil, numFmt.format(allowed)) : "–";

						sb.append("| `").append(vName).append("` | ")
								.append(slotLen).append("s | ")
								.append(numFmt.format(vReq)).append(" | ")
								.append(numFmt.format(vBlk)).append(" | ")
								.append(String.format(Locale.GERMANY, "%.2f%%", vQuote)).append(" | ")
								.append("**`").append(String.format(Locale.GERMANY, "%.1f", pReqRate)).append(" req/s`** | ")
								.append(numFmt.format(pRawReq)).append(" in ").append(pReqDur).append("s | ")
								.append(utilStr).append(" |\n");
					} catch (Exception ignored) {}
				}
				sb.append("\n");
			}
		}

		sb.append("---\n\n");

		// Polling Connectivity & Latency Distribution
		sb.append("## 🌐 3. Flotten-Konnektivität & Datenabrufzeiten (Polling-Audit)\n\n");

		try {
			long totPolls = (Long) rawPollSummary.getClass().getMethod("totalPolls").invoke(rawPollSummary);
			long succPolls = (Long) rawPollSummary.getClass().getMethod("successPolls").invoke(rawPollSummary);
			long warnPolls = (Long) rawPollSummary.getClass().getMethod("warningPolls").invoke(rawPollSummary);
			long errPolls = (Long) rawPollSummary.getClass().getMethod("errorPolls").invoke(rawPollSummary);
			long minMs = (Long) rawPollSummary.getClass().getMethod("minMs").invoke(rawPollSummary);
			double avgMs = (Double) rawPollSummary.getClass().getMethod("avgMs").invoke(rawPollSummary);
			long maxMs = (Long) rawPollSummary.getClass().getMethod("maxMs").invoke(rawPollSummary);

			long bLt50 = (Long) rawPollSummary.getClass().getMethod("bucketLt50").invoke(rawPollSummary);
			long b50to200 = (Long) rawPollSummary.getClass().getMethod("bucket50to200").invoke(rawPollSummary);
			long b200to500 = (Long) rawPollSummary.getClass().getMethod("bucket200to500").invoke(rawPollSummary);
			long bGte500 = (Long) rawPollSummary.getClass().getMethod("bucketGte500").invoke(rawPollSummary);

			double avail = totPolls > 0 ? (succPolls * 100.0) / totPolls : 100.0;

			sb.append("* **Gesamtzahl Abrufe:** ").append(numFmt.format(totPolls)).append("\n");
			sb.append("* **Erfolgsquote (Verfügbarkeit):** **").append(String.format(Locale.GERMANY, "%.2f%%", avail)).append("** (").append(numFmt.format(succPolls)).append(" erfolgreich)\n");
			sb.append("* **Warnungen / Fehler:** ").append(warnPolls).append(" Warnungen • ").append(errPolls).append(" Fehler\n");
			sb.append("* **Antwortzeiten:** Min: `").append(minMs).append("ms` • Avg: `").append(String.format(Locale.GERMANY, "%.1f", avgMs)).append("ms` • Max: `").append(maxMs).append("ms`\n\n");

			sb.append("### Häufigkeitsverteilung der Abrufzeiten (Latenz-Histogramm)\n\n");
			sb.append("| Latenz-Intervall | Beschreibung | Anzahl Abrufe | Anteil an Gesamt-Polls |\n");
			sb.append("| :--- | :--- | :--- | :--- |\n");

			double pLt50 = totPolls > 0 ? (bLt50 * 100.0) / totPolls : 0.0;
			double p50to200 = totPolls > 0 ? (b50to200 * 100.0) / totPolls : 0.0;
			double p200to500 = totPolls > 0 ? (b200to500 * 100.0) / totPolls : 0.0;
			double pGte500 = totPolls > 0 ? (bGte500 * 100.0) / totPolls : 0.0;
			double pErr = totPolls > 0 ? (errPolls * 100.0) / totPolls : 0.0;

			sb.append("| **`< 50 ms`** | ⚡ Sehr schnell (Optimal) | ").append(numFmt.format(bLt50)).append(" | ").append(String.format(Locale.GERMANY, "%.1f%%", pLt50)).append(" |\n");
			sb.append("| **`50 – 200 ms`** | 🟢 Normaler Regelbereich | ").append(numFmt.format(b50to200)).append(" | ").append(String.format(Locale.GERMANY, "%.1f%%", p50to200)).append(" |\n");
			sb.append("| **`200 – 500 ms`** | 🟡 Erhöhte Last / Netzwerklatenz | ").append(numFmt.format(b200to500)).append(" | ").append(String.format(Locale.GERMANY, "%.1f%%", p200to500)).append(" |\n");
			sb.append("| **`> 500 ms`** | 🟠 Verlangsamte Antwort (Slow Poll) | ").append(numFmt.format(bGte500)).append(" | ").append(String.format(Locale.GERMANY, "%.1f%%", pGte500)).append(" |\n");
			sb.append("| **Fehler / Timeout** | 🔴 Fehlgeschlagene Abrufe | ").append(numFmt.format(errPolls)).append(" | ").append(String.format(Locale.GERMANY, "%.1f%%", pErr)).append(" |\n\n");

		} catch (Exception e) {
			sb.append("*Keine Polling-Statistiken verfügbar.*\n\n");
		}

		// Server Outages Table
		sb.append("### ⚠️ Aufgetretene Verbindungsausfälle & Fehler\n\n");
		if (rawOutages == null || rawOutages.isEmpty()) {
			sb.append("✅ *Keine Verbindungsabbrüche oder Nichterreichbarkeiten am heutigen Tag aufgezeichnet.*\n\n");
		} else {
			sb.append("| Server | Uhrzeit | HTTP-Code | Latenz | Fehlermeldung |\n");
			sb.append("| :--- | :--- | :--- | :--- | :--- |\n");
			for (Object outObj : rawOutages) {
				try {
					String sId = (String) outObj.getClass().getMethod("serverId").invoke(outObj);
					Instant pTime = (Instant) outObj.getClass().getMethod("pollTime").invoke(outObj);
					int httpCode = (Integer) outObj.getClass().getMethod("httpStatusCode").invoke(outObj);
					long respMs = (Long) outObj.getClass().getMethod("responseTimeMs").invoke(outObj);
					String errMsg = (String) outObj.getClass().getMethod("errorMessage").invoke(outObj);

					String timeFormatted = pTime != null ? pTime.atZone(ZoneId.systemDefault()).format(DATETIME_FORMATTER) : "–";
					String cleanErr = errMsg != null ? errMsg.replace("|", "/") : "Unknown error";
					if (cleanErr.length() > 80) cleanErr = cleanErr.substring(0, 77) + "...";

					sb.append("| `").append(sId).append("` | ")
							.append(timeFormatted).append(" | ")
							.append(httpCode > 0 ? httpCode : "–").append(" | ")
							.append(respMs).append("ms | `")
							.append(cleanErr).append("` |\n");
				} catch (Exception ignored) {}
			}
			sb.append("\n");
		}

		sb.append("---\n\n");

		// Threat Highlights
		sb.append("## 🚨 4. Sicherheits- & Angriffs-Highlights\n\n");

		if (topClients.isEmpty()) {
			sb.append("✅ *Keine blockierten Clients für diesen Tag erfasst. Das System lief vollständig unbeeinträchtigt.*\n\n");
		} else {
			sb.append("### Top 10 Auffälligste geblockte Adressen / Subnetze\n\n");
			sb.append("| IP / Subnetz | Gesamt-Anfragen | Block-Vorfälle | ASN / Betreiber | Land | Client-Typ |\n");
			sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

			for (TopOffenderSummary top : topClients) {
				String asnStr = top.asn() != null ? "AS" + top.asn() + (top.asOrg() != null ? " (" + top.asOrg() + ")" : "") : "Unbekannt";
				String country = top.countryCode() != null && !top.countryCode().isBlank() ? top.countryCode() : "–";
				String clientType = top.clientType() != null ? top.clientType().name() : "UNKNOWN";

				sb.append("| `").append(top.clientKey()).append("` | ")
						.append(numFmt.format(top.totalBlockedRequests())).append(" | ")
						.append(numFmt.format(top.totalBlockIncidents())).append(" | ")
						.append(asnStr).append(" | ")
						.append(country).append(" | `")
						.append(clientType).append("` |\n");
			}
			sb.append("\n");
		}

		if (!topAsns.isEmpty()) {
			sb.append("### Hauptverursachende Autonome Systeme (ASNs)\n\n");
			sb.append("| ASN | Betreiber / Organisation | Anfragen | Vorfälle |\n");
			sb.append("| :--- | :--- | :--- | :--- |\n");

			for (TopOffenderSummary asnTop : topAsns) {
				String asnLabel = asnTop.clientKey();
				String org = asnTop.asOrg() != null && !asnTop.asOrg().isBlank() ? asnTop.asOrg() : "–";
				sb.append("| `").append(asnLabel).append("` | ")
						.append(org).append(" | ")
						.append(numFmt.format(asnTop.totalBlockedRequests())).append(" | ")
						.append(numFmt.format(asnTop.totalBlockIncidents())).append(" |\n");
			}
			sb.append("\n");
		}

		sb.append("---\n\n");
		sb.append("*Dieser Bericht wurde automatisiert vom Anti-DoS Collector generiert und verbleibt permanent im System archiviert.*  \n");

		return sb.toString();
	}
}
