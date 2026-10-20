package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.model.IntelSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing and managing IP intelligence sources.
 */
@Repository
@SuppressWarnings("null")
public class IntelSourceRepository {

	private final JdbcTemplate jdbcTemplate;

	public IntelSourceRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<IntelSource> ROW_MAPPER = (rs, rowNum) -> {
		Timestamp syncedTs = rs.getTimestamp("last_synced_at");
		return new IntelSource(
				rs.getString("source_key"),
				rs.getString("source_type"),
				rs.getString("name"),
				rs.getString("category"),
				rs.getString("url"),
				rs.getLong("version"),
				syncedTs != null ? syncedTs.toInstant() : null,
				rs.getString("status"),
				rs.getInt("prefix_count"),
				rs.getString("last_error")
		);
	};

	public void upsert(IntelSource source) {
		String sql = """
				INSERT INTO intel_source (source_key, source_type, name, category, url, version, last_synced_at, status, prefix_count, last_error)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (source_key) DO UPDATE SET
				    source_type = EXCLUDED.source_type,
				    name = EXCLUDED.name,
				    category = EXCLUDED.category,
				    url = EXCLUDED.url,
				    status = EXCLUDED.status,
				    last_error = EXCLUDED.last_error
				""";
		jdbcTemplate.update(
				sql,
				source.sourceKey(),
				source.sourceType(),
				source.name(),
				source.category(),
				source.url(),
				source.version(),
				source.lastSyncedAt() != null ? Timestamp.from(source.lastSyncedAt()) : null,
				source.status(),
				source.prefixCount(),
				source.lastError()
		);
	}

	public void updateSyncStatus(String sourceKey, String status, int prefixCount, String error, Instant syncedAt) {
		String sql = """
				UPDATE intel_source SET
				    status = ?,
				    prefix_count = ?,
				    last_error = ?,
				    last_synced_at = ?,
				    version = version + 1
				WHERE source_key = ?
				""";
		jdbcTemplate.update(sql, status, prefixCount, error, syncedAt != null ? Timestamp.from(syncedAt) : null, sourceKey);
	}

	public Optional<IntelSource> findByKey(String sourceKey) {
		List<IntelSource> list = jdbcTemplate.query(
				"SELECT * FROM intel_source WHERE source_key = ? LIMIT 1",
				ROW_MAPPER, sourceKey);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	public List<IntelSource> findAll() {
		return jdbcTemplate.query("SELECT * FROM intel_source ORDER BY name ASC", ROW_MAPPER);
	}

	public int deleteNotIn(List<String> activeKeys) {
		if (activeKeys == null || activeKeys.isEmpty()) {
			return jdbcTemplate.update("DELETE FROM intel_source");
		}
		StringBuilder sql = new StringBuilder("DELETE FROM intel_source WHERE source_key NOT IN (");
		for (int i = 0; i < activeKeys.size(); i++) {
			sql.append(i > 0 ? ",?" : "?");
		}
		sql.append(")");
		return jdbcTemplate.update(sql.toString(), activeKeys.toArray());
	}
}
