package org.henbru.antidos.collector.system;

import java.sql.Connection;
import javax.sql.DataSource;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import com.zaxxer.hikari.HikariDataSource;

/**
 * Service managing database storage health, freelist diagnostics, and space compaction (VACUUM)
 * for SQLite standalone deployments.
 */
@Service
public class DatabaseMaintenanceService {

	private static final Logger log = LoggerFactory.getLogger(DatabaseMaintenanceService.class);

	private final JdbcTemplate jdbcTemplate;
	private final DataSource dataSource;
	private final CollectorProperties properties;

	@Autowired
	public DatabaseMaintenanceService(JdbcTemplate jdbcTemplate, DataSource dataSource, CollectorProperties properties) {
		this.jdbcTemplate = jdbcTemplate;
		this.dataSource = dataSource;
		this.properties = properties;
	}

	public boolean isSqlite() {
		if (dataSource instanceof HikariDataSource hikari) {
			String rawUrl = hikari.getJdbcUrl();
			if (rawUrl != null && rawUrl.startsWith("jdbc:sqlite:")) {
				return true;
			}
		}
		try (Connection conn = dataSource.getConnection()) {
			String prod = conn.getMetaData().getDatabaseProductName();
			return prod != null && prod.toLowerCase().contains("sqlite");
		} catch (Exception e) {
			return false;
		}
	}

	public FreelistInfo getFreelistInfo() {
		if (!isSqlite()) {
			return new FreelistInfo(0, 0, 0, "0 B");
		}
		try {
			Long pages = jdbcTemplate.queryForObject("PRAGMA freelist_count", Long.class);
			Long size = jdbcTemplate.queryForObject("PRAGMA page_size", Long.class);
			long p = pages != null ? pages : 0L;
			long s = size != null ? size : 4096L;
			long bytes = p * s;
			return new FreelistInfo(p, s, bytes, formatBytes(bytes));
		} catch (Exception e) {
			log.warn("Could not query SQLite freelist info: {}", e.getMessage());
			return new FreelistInfo(0, 0, 0, "N/A");
		}
	}

	public VacuumResult vacuum() {
		if (!isSqlite()) {
			return new VacuumResult(false, 0, "Database is not SQLite; storage compaction is managed by native RDBMS.");
		}
		FreelistInfo before = getFreelistInfo();
		long start = System.currentTimeMillis();
		try {
			log.info("Executing SQLite VACUUM to reclaim space (current freelist: {})...", before.formattedBytes());
			jdbcTemplate.execute("VACUUM");
			long durationMs = System.currentTimeMillis() - start;
			String msg = String.format("SQLite database compacted successfully in %dms (freed approximately %s).",
					durationMs, before.formattedBytes());
			log.info(msg);
			return new VacuumResult(true, durationMs, msg);
		} catch (Exception e) {
			log.error("Failed to execute SQLite VACUUM: {}", e.getMessage(), e);
			return new VacuumResult(false, 0, "VACUUM failed: " + e.getMessage());
		}
	}

	public boolean vacuumIfFreelistExceeds(long thresholdBytes) {
		if (!isSqlite()) {
			return false;
		}
		FreelistInfo info = getFreelistInfo();
		if (info.freeBytes() >= thresholdBytes) {
			log.info("SQLite freelist ({} bytes, {}) exceeds threshold ({} bytes). Running auto-vacuum...",
					info.freeBytes(), info.formattedBytes(), thresholdBytes);
			VacuumResult res = vacuum();
			return res.success();
		}
		return false;
	}

	private static String formatBytes(long bytes) {
		if (bytes < 1024) return bytes + " B";
		int z = (63 - Long.numberOfLeadingZeros(bytes)) / 10;
		return String.format("%.1f %sB", (double) bytes / (1L << (z * 10)), " KMGTPE".charAt(z));
	}

	public record FreelistInfo(long freelistPages, long pageSize, long freeBytes, String formattedBytes) {}
	public record VacuumResult(boolean success, long durationMs, String message) {}
}
