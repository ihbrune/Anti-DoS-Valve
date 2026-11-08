package org.henbru.antidos.collector.storage;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Storage repository for dynamic system-wide configuration settings stored in the database.
 * Settings stored here take precedence over static application.yaml properties.
 */
@Repository
public class SystemSettingsRepository {

	private static final Logger log = LoggerFactory.getLogger(SystemSettingsRepository.class);

	private final JdbcTemplate jdbcTemplate;

	public SystemSettingsRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	public record SystemSettingEntry(
			String key,
			String value,
			String description,
			Instant updatedAt,
			String updatedBy
	) {}

	public Optional<String> getString(String key) {
		return StorageRetryUtil.executeWithRetry("getSetting-" + key, () -> {
			String sql = "SELECT setting_value FROM system_settings WHERE setting_key = ?";
			return jdbcTemplate.query(sql, (rs, rowNum) -> rs.getString("setting_value"), key)
					.stream()
					.findFirst();
		});
	}

	public Optional<Boolean> getBoolean(String key) {
		return getString(key).map(val -> {
			String trimmed = val.trim().toLowerCase();
			return "true".equals(trimmed) || "1".equals(trimmed) || "yes".equals(trimmed) || "on".equals(trimmed);
		});
	}

	public Optional<Integer> getInt(String key) {
		return getString(key).flatMap(val -> {
			try {
				return Optional.of(Integer.parseInt(val.trim()));
			} catch (NumberFormatException e) {
				log.warn("Invalid integer value in system_settings for key '{}': {}", key, val);
				return Optional.empty();
			}
		});
	}

	public Optional<Long> getLong(String key) {
		return getString(key).flatMap(val -> {
			try {
				return Optional.of(Long.parseLong(val.trim()));
			} catch (NumberFormatException e) {
				log.warn("Invalid long value in system_settings for key '{}': {}", key, val);
				return Optional.empty();
			}
		});
	}

	public Optional<Double> getDouble(String key) {
		return getString(key).flatMap(val -> {
			try {
				return Optional.of(Double.parseDouble(val.trim()));
			} catch (NumberFormatException e) {
				log.warn("Invalid double value in system_settings for key '{}': {}", key, val);
				return Optional.empty();
			}
		});
	}

	public Map<String, SystemSettingEntry> findAll() {
		return StorageRetryUtil.executeWithRetry("findAllSettings", () -> {
			String sql = "SELECT setting_key, setting_value, description, updated_at, updated_by FROM system_settings ORDER BY setting_key ASC";
			Map<String, SystemSettingEntry> map = new LinkedHashMap<>();
			jdbcTemplate.query(sql, (rs) -> {
				SystemSettingEntry entry = mapRow(rs);
				map.put(entry.key(), entry);
			});
			return map;
		});
	}

	public void setSetting(String key, String value, String description, String updatedBy) {
		StorageRetryUtil.executeWithRetry("setSetting-" + key, () -> {
			Instant now = Instant.now();
			// Upsert syntax compatible with SQLite 3.24+ and PostgreSQL 9.5+
			String sql = """
					INSERT INTO system_settings (setting_key, setting_value, description, updated_at, updated_by)
					VALUES (?, ?, ?, ?, ?)
					ON CONFLICT(setting_key) DO UPDATE SET
					    setting_value = excluded.setting_value,
					    description = COALESCE(excluded.description, system_settings.description),
					    updated_at = excluded.updated_at,
					    updated_by = excluded.updated_by
					""";
			jdbcTemplate.update(sql, key, value, description, Timestamp.from(now), updatedBy != null ? updatedBy : "SYSTEM");
			return null;
		});
	}

	public boolean deleteSetting(String key) {
		return StorageRetryUtil.executeWithRetry("deleteSetting-" + key, () -> {
			String sql = "DELETE FROM system_settings WHERE setting_key = ?";
			return jdbcTemplate.update(sql, key) > 0;
		});
	}

	private static SystemSettingEntry mapRow(ResultSet rs) throws SQLException {
		Timestamp ts = rs.getTimestamp("updated_at");
		return new SystemSettingEntry(
				rs.getString("setting_key"),
				rs.getString("setting_value"),
				rs.getString("description"),
				ts != null ? ts.toInstant() : Instant.now(),
				rs.getString("updated_by")
		);
	}
}

