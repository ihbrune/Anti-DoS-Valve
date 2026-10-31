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
import org.henbru.antidos.collector.model.DailyReportNote;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.DailyReportNoteRepository;
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
	private final DailyReportNoteRepository noteRepository;
	private final MonitoredValveRepository valveRepository;
	private final ClientEventRepository clientEventRepository;
	private final AnnotationMarkdownService markdownService;

	public DailyReportService(
			JdbcTemplate jdbcTemplate,
			DailyReportRepository reportRepository,
			DailyReportNoteRepository noteRepository,
			MonitoredValveRepository valveRepository,
			ClientEventRepository clientEventRepository,
			AnnotationMarkdownService markdownService,
			CollectorProperties properties
	) {
		this.jdbcTemplate = jdbcTemplate;
		this.reportRepository = reportRepository;
		this.noteRepository = noteRepository;
		this.valveRepository = valveRepository;
		this.clientEventRepository = clientEventRepository;
		this.markdownService = markdownService;
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

		NumberFormat numFmt = NumberFormat.getInstance(Locale.US);

		// 1. Load active valves configuration for slotLength & threshold context
		Map<String, MonitoredValve> valveConfigMap = new HashMap<>();
		for (MonitoredValve mv : valveRepository.findAll()) {
			valveConfigMap.put(mv.serverId() + "#" + mv.valveName(), mv);
		}

		// 2. Aggregate Slot Snapshots & Client Events (Fleet Totals)
		long totalRequests = 0;
		long totalBlocked = 0;
		long totalMarked = 0;
		long fleetBlockedSlots = 0;
		long fleetMarkedSlots = 0;
		long fleetTotalSlots = 0;
		int serverCount = 0;

		try {
			Long reqSum = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(total_requests), 0) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			totalRequests = reqSum != null ? reqSum : 0L;

			Long blockedReqSum = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(request_count), 0) FROM client_events WHERE status = 'BLOCKED' AND slot_time >= ? AND slot_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));

			Long blockedCountersSum = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(blocked_counters), 0) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));

			totalBlocked = (blockedReqSum != null && blockedReqSum > 0)
					? blockedReqSum
					: (blockedCountersSum != null ? blockedCountersSum : 0L);

			Long markedReqSum = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(request_count), 0) FROM client_events WHERE status = 'MARKED' AND slot_time >= ? AND slot_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));

			Long markedCountersSum = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(COALESCE(marked_counters, 0)), 0) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));

			totalMarked = (markedReqSum != null && markedReqSum > 0)
					? markedReqSum
					: (markedCountersSum != null ? markedCountersSum : 0L);

			Long blkSlots = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(CASE WHEN blocked_counters > 0 THEN 1 ELSE 0 END), 0) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			fleetBlockedSlots = blkSlots != null ? blkSlots : 0L;

			Long mrkSlots = jdbcTemplate.queryForObject(
					"SELECT COALESCE(SUM(CASE WHEN COALESCE(marked_counters, 0) > 0 THEN 1 ELSE 0 END), 0) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			fleetMarkedSlots = mrkSlots != null ? mrkSlots : 0L;

			Long totSlots = jdbcTemplate.queryForObject(
					"SELECT COUNT(*) FROM slot_snapshots WHERE start_time >= ? AND start_time < ?",
					Long.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			fleetTotalSlots = totSlots != null ? totSlots : 0L;

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
				String modeLabel,
				long totalRequests,
				long blockedRequests,
				long markedRequests,
				int slotCount,
				int blockedSlotCount,
				int markedSlotCount,
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
				double peakMarkRatePerSec,
				long peakRawMarked,
				long peakMarkDurationSec,
				Instant peakMarkTime,
				double peakUtilizationPercent
		) {
		}

		List<ValveAggregate> valveAggregates = new ArrayList<>();
		double fleetPeakReqRate = 0.0;
		double fleetPeakBlockRate = 0.0;
		double fleetPeakMarkRate = 0.0;
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

		String peakMarkServer = null;
		String peakMarkValve = null;
		Instant fleetPeakMarkTime = null;
		long fleetPeakMarkRaw = 0;
		long fleetPeakMarkDuration = 0;

		// Query blocked & marked requests per valve from client_events
		Map<String, Long> valveBlockedReqsMap = new HashMap<>();
		Map<String, Long> valveMarkedReqsMap = new HashMap<>();
		try {
			String blkReqQuery = """
					SELECT server_id, valve_name,
					       COALESCE(SUM(CASE WHEN status = 'BLOCKED' THEN request_count ELSE 0 END), 0) AS blocked_reqs,
					       COALESCE(SUM(CASE WHEN status = 'MARKED' THEN request_count ELSE 0 END), 0) AS marked_reqs
					FROM client_events
					WHERE status IN ('BLOCKED', 'MARKED') AND slot_time >= ? AND slot_time < ?
					GROUP BY server_id, valve_name
					""";
			List<Map<String, Object>> blkRows = jdbcTemplate.queryForList(
					blkReqQuery, Timestamp.from(startInstant), Timestamp.from(endInstant));
			for (Map<String, Object> r : blkRows) {
				String key = r.get("server_id") + "#" + r.get("valve_name");
				valveBlockedReqsMap.put(key, ((Number) r.get("blocked_reqs")).longValue());
				valveMarkedReqsMap.put(key, ((Number) r.get("marked_reqs")).longValue());
			}
		} catch (Exception e) {
			log.warn("Error querying valve blocked/marked requests for {}: {}", dateStr, e.getMessage());
		}

		try {
			String valveQuery = """
					SELECT server_id, valve_name,
					       COALESCE(SUM(total_requests), 0) AS req_sum,
					       COALESCE(SUM(blocked_counters), 0) AS block_counters_sum,
					       COALESCE(SUM(COALESCE(marked_counters, 0)), 0) AS mark_counters_sum,
					       COUNT(*) AS slot_count,
					       COALESCE(SUM(CASE WHEN blocked_counters > 0 THEN 1 ELSE 0 END), 0) AS blocked_slot_count,
					       COALESCE(SUM(CASE WHEN COALESCE(marked_counters, 0) > 0 THEN 1 ELSE 0 END), 0) AS marked_slot_count
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
				long vBlockCountersSum = ((Number) row.get("block_counters_sum")).longValue();
				long vMarkCountersSum = ((Number) row.get("mark_counters_sum")).longValue();
				int slotCount = ((Number) row.get("slot_count")).intValue();
				int blockedSlotCount = ((Number) row.get("blocked_slot_count")).intValue();
				int markedSlotCount = ((Number) row.get("marked_slot_count")).intValue();

				long vBlockedRequests = valveBlockedReqsMap.getOrDefault(sId + "#" + vName, 0L);
				if (vBlockedRequests == 0 && vBlockCountersSum > 0) {
					vBlockedRequests = vBlockCountersSum;
				}

				long vMarkedRequests = valveMarkedReqsMap.getOrDefault(sId + "#" + vName, 0L);
				if (vMarkedRequests == 0 && vMarkCountersSum > 0) {
					vMarkedRequests = vMarkCountersSum;
				}

				MonitoredValve cfg = valveConfigMap.get(sId + "#" + vName);
				int slotLen = cfg != null && cfg.slotLength() > 0 ? cfg.slotLength() : 10;
				int allowedPerSlot = cfg != null ? cfg.allowedRequestsPerSlot() : 0;
				String modeLabel = "BLOCKING";
				if (cfg != null) {
					if ("MARKING".equalsIgnoreCase(cfg.monitorMode())) {
						modeLabel = "MARKING";
					} else if (cfg.simulationMode()) {
						modeLabel = "SIMULATION";
					}
				} else if (vMarkedRequests > 0 && vBlockedRequests == 0) {
					modeLabel = "MARKING";
				}

				// Query candidate peak request slot for this valve
				List<SlotSnapshot> peakReqSlots = jdbcTemplate.query(
						"SELECT * FROM slot_snapshots WHERE server_id = ? AND valve_name = ? AND start_time >= ? AND start_time < ? ORDER BY total_requests DESC LIMIT 1",
						(rs, rowNum) -> new SlotSnapshot(
								rs.getLong("id"), rs.getString("server_id"), rs.getString("valve_name"),
								rs.getLong("slot_key"), rs.getTimestamp("start_time").toInstant(),
								rs.getTimestamp("end_time").toInstant(), rs.getLong("total_requests"),
								rs.getInt("active_counters"), rs.getInt("blocked_counters"), rs.getInt("marked_counters"),
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
								rs.getInt("active_counters"), rs.getInt("blocked_counters"), rs.getInt("marked_counters"),
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

				// Query candidate peak marked slot for this valve
				List<SlotSnapshot> peakMarkSlots = jdbcTemplate.query(
						"SELECT * FROM slot_snapshots WHERE server_id = ? AND valve_name = ? AND start_time >= ? AND start_time < ? ORDER BY COALESCE(marked_counters, 0) DESC LIMIT 1",
						(rs, rowNum) -> new SlotSnapshot(
								rs.getLong("id"), rs.getString("server_id"), rs.getString("valve_name"),
								rs.getLong("slot_key"), rs.getTimestamp("start_time").toInstant(),
								rs.getTimestamp("end_time").toInstant(), rs.getLong("total_requests"),
								rs.getInt("active_counters"), rs.getInt("blocked_counters"), rs.getInt("marked_counters"),
								rs.getBoolean("is_completed"), rs.getTimestamp("last_polled_at").toInstant()
						), sId, vName, Timestamp.from(startInstant), Timestamp.from(endInstant));

				double peakMarkRate = 0.0;
				long peakRawMrk = 0;
				long peakMrkDuration = slotLen;
				Instant peakMrkTime = null;

				if (!peakMarkSlots.isEmpty()) {
					SlotSnapshot s = peakMarkSlots.getFirst();
					peakRawMrk = s.markedCounters();
					long dur = Math.max(1, Duration.between(s.startTime(), s.endTime()).toSeconds());
					peakMrkDuration = dur;
					peakMarkRate = (double) peakRawMrk / dur;
					peakMrkTime = s.startTime();

					if (peakMarkRate > fleetPeakMarkRate) {
						fleetPeakMarkRate = peakMarkRate;
						peakMarkServer = sId;
						peakMarkValve = vName;
						fleetPeakMarkTime = peakMrkTime;
						fleetPeakMarkRaw = peakRawMrk;
						fleetPeakMarkDuration = peakMrkDuration;
					}
				}

				double peakUtilization = (allowedPerSlot > 0 && peakRawReq > 0)
						? ((double) peakRawReq / allowedPerSlot) * 100.0 : 0.0;

				valveAggregates.add(new ValveAggregate(
						sId, vName, modeLabel, vReqSum, vBlockedRequests, vMarkedRequests,
						slotCount, blockedSlotCount, markedSlotCount, slotLen, allowedPerSlot,
						peakReqRate, peakRawReq, peakReqDuration, peakReqTime,
						peakBlockRate, peakRawBlk, peakBlkDuration, peakBlkTime,
						peakMarkRate, peakRawMrk, peakMrkDuration, peakMrkTime,
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
		int distinctMarkedClients = 0;
		int totalIncidents = 0;
		int totalMarkedIncidents = 0;
		try {
			Integer dbc = jdbcTemplate.queryForObject(
					"SELECT COUNT(DISTINCT client_key) FROM client_events WHERE status = 'BLOCKED' AND slot_time >= ? AND slot_time < ?",
					Integer.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			distinctBlockedClients = dbc != null ? dbc : 0;

			Integer dmc = jdbcTemplate.queryForObject(
					"SELECT COUNT(DISTINCT client_key) FROM client_events WHERE status = 'MARKED' AND slot_time >= ? AND slot_time < ?",
					Integer.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			distinctMarkedClients = dmc != null ? dmc : 0;

			Integer inc = jdbcTemplate.queryForObject(
					"SELECT COUNT(*) FROM client_events WHERE status = 'BLOCKED' AND slot_time >= ? AND slot_time < ?",
					Integer.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			totalIncidents = inc != null ? inc : 0;

			Integer mrkInc = jdbcTemplate.queryForObject(
					"SELECT COUNT(*) FROM client_events WHERE status = 'MARKED' AND slot_time >= ? AND slot_time < ?",
					Integer.class, Timestamp.from(startInstant), Timestamp.from(endInstant));
			totalMarkedIncidents = mrkInc != null ? mrkInc : 0;
		} catch (Exception e) {
			log.warn("Error querying incident counts for {}: {}", dateStr, e.getMessage());
		}

		List<TopOffenderSummary> topClients = Collections.emptyList();
		List<TopOffenderSummary> topAsns = Collections.emptyList();
		List<TopOffenderSummary> topMarkedClients = Collections.emptyList();
		try {
			topClients = clientEventRepository.findTopOffendersFiltered(
					null, null, startInstant, endInstant, null, null, null, null, "BLOCKED", "client_key", 10);
			topAsns = clientEventRepository.findTopOffendersFiltered(
					null, null, startInstant, endInstant, null, null, null, null, "BLOCKED", "ASN", 5);
			topMarkedClients = clientEventRepository.findTopOffendersFiltered(
					null, null, startInstant, endInstant, null, null, null, null, "MARKED", "client_key", "MARKED", 5);
		} catch (Exception e) {
			log.warn("Error querying top offenders for {}: {}", dateStr, e.getMessage());
		}

		// 6. Overall Status Classification (strictly based on hard HTTP 429 blocks, never soft marking/simulation)
		String status;
		double blockRateFleet = totalRequests > 0 ? (totalBlocked * 100.0) / totalRequests : 0.0;
		double markRateFleet = totalRequests > 0 ? (totalMarked * 100.0) / totalRequests : 0.0;
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
		Optional<DailyReportNote> dayNote = noteRepository.findByReportDate(dateStr);
		String noteMarkdown = dayNote.map(DailyReportNote::noteMarkdown).orElse(null);

		String markdown = buildMarkdownReport(
				reportDate, status, totalRequests, totalBlocked, totalMarked, blockRateFleet, markRateFleet,
				fleetBlockedSlots, fleetMarkedSlots, fleetTotalSlots,
				serverCount, distinctBlockedClients, distinctMarkedClients, totalIncidents, totalMarkedIncidents,
				fleetPeakReqRate, fleetPeakReqRaw, fleetPeakReqDuration, peakReqServer, peakReqValve, fleetPeakReqTime,
				fleetPeakBlockRate, fleetPeakBlockRaw, fleetPeakBlockDuration, peakBlockServer, peakBlockValve, fleetPeakBlockTime,
				fleetPeakMarkRate, fleetPeakMarkRaw, fleetPeakMarkDuration, peakMarkServer, peakMarkValve, fleetPeakMarkTime,
				valveAggregates, pollSummary, serverPollStats, outages, topClients, topAsns, topMarkedClients, noteMarkdown, numFmt
		);

		DailyReport report = new DailyReport(
				null,
				dateStr,
				status,
				totalRequests,
				totalBlocked,
				totalMarked,
				fleetPeakReqRate,
				fleetPeakBlockRate,
				fleetPeakMarkRate,
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
		log.info("Daily operational report for {} completed in {}ms (Status: {}, TotalReq: {}, Peaks: {} req/s, {} blk/s, {} mrk/s)",
				dateStr, durationMs, status, totalRequests,
				String.format(Locale.US, "%.1f", fleetPeakReqRate),
				String.format(Locale.US, "%.1f", fleetPeakBlockRate),
				String.format(Locale.US, "%.1f", fleetPeakMarkRate));

		return report;
	}

	private String buildMarkdownReport(
			LocalDate date,
			String status,
			long totalRequests,
			long totalBlocked,
			long totalMarked,
			double blockRateFleet,
			double markRateFleet,
			long fleetBlockedSlots,
			long fleetMarkedSlots,
			long fleetTotalSlots,
			int serverCount,
			int distinctBlockedClients,
			int distinctMarkedClients,
			int totalIncidents,
			int totalMarkedIncidents,
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
			double fleetPeakMarkRate,
			long fleetPeakMarkRaw,
			long fleetPeakMarkDuration,
			String peakMarkServer,
			String peakMarkValve,
			Instant fleetPeakMarkTime,
			List<?> rawValveAggregates,
			Object rawPollSummary,
			List<?> rawServerPollStats,
			List<?> rawOutages,
			List<TopOffenderSummary> topClients,
			List<TopOffenderSummary> topAsns,
			List<TopOffenderSummary> topMarkedClients,
			String noteMarkdown,
			NumberFormat numFmt
	) {
		StringBuilder sb = new StringBuilder();

		String statusBadge = switch (status) {
			case "ATTACK_MITIGATED" -> "🔴 **ATTACK DETECTED & MITIGATED** (Active DoS wave mitigated)";
			case "DEGRADED" -> "🟡 **DEGRADED PERFORMANCE** (Elevated latencies or node outages)";
			case "WARNING" -> "🟡 **WARNING** (Sporadic warnings or timeout spikes)";
			default -> "🟢 **ALL SYSTEMS OPERATIONAL** (Nominal fleet operations)";
		};

		sb.append("# 🛡️ Anti-DoS Fleet Operational Report — ").append(date).append("\n\n");
		sb.append("> **Fleet Status:** ").append(statusBadge).append("  \n");
		sb.append("> **Analysis Period:** `").append(date).append(" 00:00:00` to `").append(date).append(" 23:59:59` (System Time)  \n");
		sb.append("> **Report Compiled:** `").append(LocalDateTime.now(ZoneId.systemDefault()).format(DATETIME_FORMATTER)).append("`\n\n");

		sb.append("---\n\n");

		// Executive Summary
		double fleetSlotRatio = fleetTotalSlots > 0 ? (fleetBlockedSlots * 100.0) / fleetTotalSlots : 0.0;
		double fleetMarkedSlotRatio = fleetTotalSlots > 0 ? (fleetMarkedSlots * 100.0) / fleetTotalSlots : 0.0;

		sb.append("## 📊 1. Executive Summary (Fleet Overview)\n\n");
		sb.append("| Metric | Daily Value | Context & Observations |\n");
		sb.append("| :--- | :--- | :--- |\n");
		sb.append("| **Total Requests** | **").append(numFmt.format(totalRequests)).append("** | Aggregate requests recorded across all monitored Valves and nodes |\n");
		sb.append("| **Blocked Requests** | **").append(numFmt.format(totalBlocked)).append("** | Denied abusive requests (HTTP 429) |\n");
		sb.append("| **Fleet Block Rate** | **").append(String.format(Locale.US, "%.2f%%", blockRateFleet)).append("** | Ratio of denied requests to total fleet traffic |\n");
		sb.append("| **Marked / Simulated Requests** | **").append(numFmt.format(totalMarked)).append("** | Soft-marked or simulation-mode threshold hits (no HTTP 429) |\n");
		sb.append("| **Fleet Mark Rate** | **").append(String.format(Locale.US, "%.2f%%", markRateFleet)).append("** | Ratio of soft-marked/simulated requests to total fleet traffic |\n");
		sb.append("| **Affected Incident Slots** | **").append(numFmt.format(fleetBlockedSlots)).append(" of ").append(numFmt.format(fleetTotalSlots))
				.append(" (").append(String.format(Locale.US, "%.2f%%", fleetSlotRatio)).append(")** | Time slots with active HTTP 429 rate-limit mitigation |\n");
		if (fleetMarkedSlots > 0 || totalMarked > 0) {
			sb.append("| **Affected Marking Slots** | **").append(numFmt.format(fleetMarkedSlots)).append(" of ").append(numFmt.format(fleetTotalSlots))
					.append(" (").append(String.format(Locale.US, "%.2f%%", fleetMarkedSlotRatio)).append(")** | Time slots with soft-marking or simulation threshold hits |\n");
		}
		sb.append("| **Active Nodes / Valves** | **").append(serverCount).append(" servers / ").append(rawValveAggregates.size()).append(" valves** | Fleet instances participating in telemetry collection |\n");
		sb.append("| **Blocked Clients** | **").append(numFmt.format(distinctBlockedClients)).append(" unique IPs** | Involved in hard HTTP 429 rate-limit blocks |\n");
		if (distinctMarkedClients > 0 || totalMarkedIncidents > 0) {
			sb.append("| **Marked Clients** | **").append(numFmt.format(distinctMarkedClients)).append(" unique IPs/subnets** | Flagged by soft-marking or simulation valves (").append(numFmt.format(totalMarkedIncidents)).append(" events) |\n");
		}
		sb.append("| **Incident Events (Client Log)** | **").append(numFmt.format(totalIncidents)).append("** | Forensic blocking incident events logged in database |\n");

		// Peak Request Rate
		sb.append("| **Peak Request Rate (Normalized)** | **`")
				.append(String.format(Locale.US, "%.1f", fleetPeakReqRate)).append(" req/s`** | ");
		if (peakReqServer != null && peakReqValve != null) {
			String timeStr = fleetPeakReqTime != null ? fleetPeakReqTime.atZone(ZoneId.systemDefault()).format(TIME_FORMATTER) : "N/A";
			sb.append(numFmt.format(fleetPeakReqRaw)).append(" requests in ").append(fleetPeakReqDuration).append("s slot on `")
					.append(peakReqServer).append("` / Valve `").append(peakReqValve).append("` (at ").append(timeStr).append(")");
		} else {
			sb.append("No traffic recorded");
		}
		sb.append(" |\n");

		// Peak Block Rate
		sb.append("| **Peak Block Rate (Normalized)** | **`")
				.append(String.format(Locale.US, "%.1f", fleetPeakBlockRate)).append(" blocks/s`** | ");
		if (peakBlockServer != null && peakBlockValve != null && fleetPeakBlockRaw > 0) {
			String timeStr = fleetPeakBlockTime != null ? fleetPeakBlockTime.atZone(ZoneId.systemDefault()).format(TIME_FORMATTER) : "N/A";
			sb.append(numFmt.format(fleetPeakBlockRaw)).append(" blocks in ").append(fleetPeakBlockDuration).append("s slot on `")
					.append(peakBlockServer).append("` / Valve `").append(peakBlockValve).append("` (at ").append(timeStr).append(")");
		} else {
			sb.append("No active rate-limit blocks occurred");
		}
		sb.append(" |\n");

		// Peak Mark Rate
		if (fleetPeakMarkRaw > 0 && peakMarkServer != null && peakMarkValve != null) {
			String timeStr = fleetPeakMarkTime != null ? fleetPeakMarkTime.atZone(ZoneId.systemDefault()).format(TIME_FORMATTER) : "N/A";
			sb.append("| **Peak Mark Rate (Normalized)** | **`")
					.append(String.format(Locale.US, "%.1f", fleetPeakMarkRate)).append(" marks/s`** | ")
					.append(numFmt.format(fleetPeakMarkRaw)).append(" marks in ").append(fleetPeakMarkDuration).append("s slot on `")
					.append(peakMarkServer).append("` / Valve `").append(peakMarkValve).append("` (at ").append(timeStr).append(") |\n");
		}
		sb.append("\n---\n\n");

		// Optional Operator Day Note (anchored with HTML comments for atomic re-embedding)
		sb.append(buildNoteSectionMarkdown(noteMarkdown));

		// Server- & Valve-Breakdown
		sb.append("## ⚡ 2. Server & Valve Telemetry (Normalized Peaks)\n\n");
		sb.append("> ℹ️ **Normalization Note:** To objectively compare Valves configured with different slot durations (e.g. 5s vs. 60s), ");
		sb.append("peak values are normalized to per-second rates (`req/s` and `blocks/s`).\n\n");

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
			sb.append("*No Valve telemetry recorded for this date.*\n\n");
		} else {
			for (Map.Entry<String, List<Object>> entry : serverMap.entrySet()) {
				String sId = entry.getKey();
				List<Object> valves = entry.getValue();

				sb.append("### Server `").append(sId).append("` (").append(valves.size()).append(" Valves)\n\n");
				sb.append("| Valve | Mode | Slot Length | Total Requests | Blocked Requests | Marked Requests | Block / Mark Rate | Affected Slots (Ratio) | Peak Rate (norm.) | Peak Slot (raw) | Peak Utilization |\n");
				sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

				for (Object vObj : valves) {
					try {
						String vName = (String) vObj.getClass().getMethod("valveName").invoke(vObj);
						String modeLabel = (String) vObj.getClass().getMethod("modeLabel").invoke(vObj);
						long vReq = (Long) vObj.getClass().getMethod("totalRequests").invoke(vObj);
						long vBlkReq = (Long) vObj.getClass().getMethod("blockedRequests").invoke(vObj);
						long vMrkReq = (Long) vObj.getClass().getMethod("markedRequests").invoke(vObj);
						int slotCnt = (Integer) vObj.getClass().getMethod("slotCount").invoke(vObj);
						int blkSlotCnt = (Integer) vObj.getClass().getMethod("blockedSlotCount").invoke(vObj);
						int mrkSlotCnt = (Integer) vObj.getClass().getMethod("markedSlotCount").invoke(vObj);
						int slotLen = (Integer) vObj.getClass().getMethod("configuredSlotLength").invoke(vObj);
						int allowed = (Integer) vObj.getClass().getMethod("allowedRequestsPerSlot").invoke(vObj);
						double pReqRate = (Double) vObj.getClass().getMethod("peakReqRatePerSec").invoke(vObj);
						long pRawReq = (Long) vObj.getClass().getMethod("peakRawRequests").invoke(vObj);
						long pReqDur = (Long) vObj.getClass().getMethod("peakReqDurationSec").invoke(vObj);
						double pUtil = (Double) vObj.getClass().getMethod("peakUtilizationPercent").invoke(vObj);

						long effectiveTriggeredReqs = vBlkReq > 0 ? vBlkReq : vMrkReq;
						int effectiveTriggeredSlots = blkSlotCnt > 0 ? blkSlotCnt : mrkSlotCnt;
						double vQuote = vReq > 0 ? (effectiveTriggeredReqs * 100.0) / vReq : 0.0;
						double slotRatio = slotCnt > 0 ? (effectiveTriggeredSlots * 100.0) / slotCnt : 0.0;
						String utilStr = allowed > 0 ? String.format(Locale.US, "%.1f%% (%s max)", pUtil, numFmt.format(allowed)) : "–";
						String slotInfo = numFmt.format(effectiveTriggeredSlots) + " / " + numFmt.format(slotCnt) + " (" + String.format(Locale.US, "%.2f%%", slotRatio) + ")";

						sb.append("| `").append(vName).append("` | `")
								.append(modeLabel).append("` | ")
								.append(slotLen).append("s | ")
								.append(numFmt.format(vReq)).append(" | ")
								.append(numFmt.format(vBlkReq)).append(" | ")
								.append(numFmt.format(vMrkReq)).append(" | ")
								.append(String.format(Locale.US, "%.2f%%", vQuote)).append(" | ")
								.append(slotInfo).append(" | ")
								.append("**`").append(String.format(Locale.US, "%.1f", pReqRate)).append(" req/s`** | ")
								.append(numFmt.format(pRawReq)).append(" in ").append(pReqDur).append("s | ")
								.append(utilStr).append(" |\n");
					} catch (Exception ignored) {}
				}
				sb.append("\n");
			}
		}

		sb.append("---\n\n");

		// Polling Connectivity & Latency Distribution
		sb.append("## 🌐 3. Fleet Connectivity & Polling Latency Audit\n\n");

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

			sb.append("* **Total Invocations:** ").append(numFmt.format(totPolls)).append("\n");
			sb.append("* **Success Rate (Availability):** **").append(String.format(Locale.US, "%.2f%%", avail)).append("** (").append(numFmt.format(succPolls)).append(" successful)\n");
			sb.append("* **Warnings / Errors:** ").append(warnPolls).append(" warnings • ").append(errPolls).append(" errors\n");
			sb.append("* **Response Times:** Min: `").append(minMs).append("ms` • Avg: `").append(String.format(Locale.US, "%.1f", avgMs)).append("ms` • Max: `").append(maxMs).append("ms`\n\n");

			sb.append("### Polling Latency Distribution Histogram\n\n");
			sb.append("| Latency Interval | Description | Invocations | Share of Total Polls |\n");
			sb.append("| :--- | :--- | :--- | :--- |\n");

			double pLt50 = totPolls > 0 ? (bLt50 * 100.0) / totPolls : 0.0;
			double p50to200 = totPolls > 0 ? (b50to200 * 100.0) / totPolls : 0.0;
			double p200to500 = totPolls > 0 ? (b200to500 * 100.0) / totPolls : 0.0;
			double pGte500 = totPolls > 0 ? (bGte500 * 100.0) / totPolls : 0.0;
			double pErr = totPolls > 0 ? (errPolls * 100.0) / totPolls : 0.0;

			sb.append("| **`< 50 ms`** | ⚡ Very Fast (Optimal) | ").append(numFmt.format(bLt50)).append(" | ").append(String.format(Locale.US, "%.1f%%", pLt50)).append(" |\n");
			sb.append("| **`50 – 200 ms`** | 🟢 Nominal Operating Range | ").append(numFmt.format(b50to200)).append(" | ").append(String.format(Locale.US, "%.1f%%", p50to200)).append(" |\n");
			sb.append("| **`200 – 500 ms`** | 🟡 Elevated Load / Network Latency | ").append(numFmt.format(b200to500)).append(" | ").append(String.format(Locale.US, "%.1f%%", p200to500)).append(" |\n");
			sb.append("| **`> 500 ms`** | 🟠 Slow Response (High Lag) | ").append(numFmt.format(bGte500)).append(" | ").append(String.format(Locale.US, "%.1f%%", pGte500)).append(" |\n");
			sb.append("| **Errors / Timeouts** | 🔴 Failed Poll Invocations | ").append(numFmt.format(errPolls)).append(" | ").append(String.format(Locale.US, "%.1f%%", pErr)).append(" |\n\n");

		} catch (Exception e) {
			sb.append("*No polling telemetry available for this date.*\n\n");
		}

		// Server Outages Table
		sb.append("### ⚠️ Connection Failures & Node Outages\n\n");
		if (rawOutages == null || rawOutages.isEmpty()) {
			sb.append("✅ *No connection dropouts or node unreachable errors recorded for this date.*\n\n");
		} else {
			sb.append("| Server | Timestamp | HTTP Code | Latency | Error Message |\n");
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
		sb.append("## 🚨 4. Threat Intelligence & Security Highlights\n\n");

		if (topClients.isEmpty()) {
			sb.append("✅ *No blocked clients recorded for this date. The fleet operated unhindered.*\n\n");
		} else {
			sb.append("### Top 10 Offending Client Addresses & Subnets (Hard Blocks / HTTP 429)\n\n");
			sb.append("| IP / Subnet | Total Requests | Blocked Requests | ASN / Operator | Country | Client Type |\n");
			sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

			for (TopOffenderSummary top : topClients) {
				String asnStr = top.asn() != null ? "AS" + top.asn() + (top.asOrg() != null ? " (" + top.asOrg() + ")" : "") : "Unknown";
				String country = top.countryCode() != null && !top.countryCode().isBlank() ? top.countryCode() : "–";
				String clientType = top.clientType() != null ? top.clientType().name() : "UNKNOWN";

				sb.append("| `").append(top.clientKey()).append("` | ")
						.append(numFmt.format(top.totalRequests())).append(" | ")
						.append(numFmt.format(top.totalBlockedRequests())).append(" | ")
						.append(asnStr).append(" | ")
						.append(country).append(" | `")
						.append(clientType).append("` |\n");
			}
			sb.append("\n");
		}

		if (!topAsns.isEmpty()) {
			sb.append("### Top Abusive Autonomous Systems (ASNs)\n\n");
			sb.append("| ASN | Operator / Organization | Total Requests | Blocked Requests |\n");
			sb.append("| :--- | :--- | :--- | :--- |\n");

			for (TopOffenderSummary asnTop : topAsns) {
				String asnLabel = asnTop.clientKey();
				String org = asnTop.asOrg() != null && !asnTop.asOrg().isBlank() ? asnTop.asOrg() : "–";
				sb.append("| `").append(asnLabel).append("` | ")
						.append(org).append(" | ")
						.append(numFmt.format(asnTop.totalRequests())).append(" | ")
						.append(numFmt.format(asnTop.totalBlockedRequests())).append(" |\n");
			}
			sb.append("\n");
		}

		if (topMarkedClients != null && !topMarkedClients.isEmpty()) {
			sb.append("### Top Marked / Monitored Clients (Soft-Marking & Simulation)\n\n");
			sb.append("| IP / Subnet | Total Requests | Marked Requests | ASN / Operator | Country | Client Type |\n");
			sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

			for (TopOffenderSummary topMrk : topMarkedClients) {
				String asnStr = topMrk.asn() != null ? "AS" + topMrk.asn() + (topMrk.asOrg() != null ? " (" + topMrk.asOrg() + ")" : "") : "Unknown";
				String country = topMrk.countryCode() != null && !topMrk.countryCode().isBlank() ? topMrk.countryCode() : "–";
				String clientType = topMrk.clientType() != null ? topMrk.clientType().name() : "UNKNOWN";

				sb.append("| `").append(topMrk.clientKey()).append("` | ")
						.append(numFmt.format(topMrk.totalRequests())).append(" | ")
						.append(numFmt.format(topMrk.totalMarkedRequests())).append(" | ")
						.append(asnStr).append(" | ")
						.append(country).append(" | `")
						.append(clientType).append("` |\n");
			}
			sb.append("\n");
		}

		sb.append("---\n\n");
		sb.append("*This operational report was automatically compiled by Anti-DoS Collector and remains permanently archived.*  \n");

		return sb.toString();
	}

	public Optional<DailyReportNote> getNote(String reportDate) {
		if (reportDate == null || reportDate.isBlank()) {
			return Optional.empty();
		}
		return noteRepository.findByReportDate(reportDate.trim());
	}

	public DailyReportNote saveNote(String reportDate, String noteMarkdown) {
		if (reportDate == null || reportDate.isBlank()) {
			throw new IllegalArgumentException("reportDate must not be blank");
		}
		String cleanDate = reportDate.trim();
		String cleanNote = noteMarkdown != null ? noteMarkdown.trim() : "";
		noteRepository.upsert(cleanDate, cleanNote);
		syncNoteIntoReportMarkdown(cleanDate, cleanNote);
		return noteRepository.findByReportDate(cleanDate).orElseThrow();
	}

	public void deleteNote(String reportDate) {
		if (reportDate == null || reportDate.isBlank()) {
			return;
		}
		String cleanDate = reportDate.trim();
		noteRepository.deleteByReportDate(cleanDate);
		syncNoteIntoReportMarkdown(cleanDate, null);
	}

	public List<String> getDatesWithNotes() {
		return noteRepository.findDatesWithNotes();
	}

	public String buildNoteSectionMarkdown(String noteMarkdown) {
		StringBuilder sb = new StringBuilder();
		sb.append("<!-- DAILY_NOTE_START -->\n");
		if (noteMarkdown != null && !noteMarkdown.isBlank()) {
			sb.append("### 📝 Operator Notes & Highlights\n\n");
			sb.append(noteMarkdown.trim()).append("\n\n");
			sb.append("---\n\n");
		}
		sb.append("<!-- DAILY_NOTE_END -->\n\n");
		return sb.toString();
	}

	private void syncNoteIntoReportMarkdown(String reportDate, String noteMarkdown) {
		Optional<DailyReport> opt = reportRepository.findByReportDate(reportDate);
		if (opt.isEmpty()) {
			return;
		}
		DailyReport report = opt.get();
		String currentMd = report.reportMarkdown();
		String noteSection = buildNoteSectionMarkdown(noteMarkdown);

		String updatedMd;
		if (currentMd.contains("<!-- DAILY_NOTE_START -->") && currentMd.contains("<!-- DAILY_NOTE_END -->")) {
			int start = currentMd.indexOf("<!-- DAILY_NOTE_START -->");
			int end = currentMd.indexOf("<!-- DAILY_NOTE_END -->") + "<!-- DAILY_NOTE_END -->".length();
			while (end < currentMd.length() && currentMd.charAt(end) == '\n') {
				end++;
			}
			updatedMd = currentMd.substring(0, start) + noteSection + currentMd.substring(end);
		} else {
			// Older report without markers: insert before Section 2
			int sec2Idx = currentMd.indexOf("## ⚡ 2.");
			if (sec2Idx != -1) {
				updatedMd = currentMd.substring(0, sec2Idx) + noteSection + currentMd.substring(sec2Idx);
			} else {
				updatedMd = currentMd + "\n\n" + noteSection;
			}
		}

		DailyReport updated = new DailyReport(
				report.id(),
				report.reportDate(),
				report.status(),
				report.totalRequests(),
				report.totalBlocked(),
				report.peakRequestsPerSec(),
				report.peakBlockedPerSec(),
				report.peakValveName(),
				report.peakServerId(),
				report.serverCount(),
				report.incidentCount(),
				updatedMd,
				report.createdAt(),
				Instant.now()
		);
		reportRepository.upsert(updated);
	}
}
