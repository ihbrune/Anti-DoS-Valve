package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.model.CrawlerFeed;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for managing configured crawler/bot IP feeds and synchronization metadata.
 */
@Repository
@SuppressWarnings("null")
public class CrawlerFeedRepository {

	private final JdbcTemplate jdbcTemplate;

	public CrawlerFeedRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<CrawlerFeed> ROW_MAPPER = (rs, rowNum) -> new CrawlerFeed(
			rs.getString("feed_key"),
			rs.getString("name"),
			rs.getString("category"),
			rs.getString("url"),
			rs.getTimestamp("last_synced_at") != null ? rs.getTimestamp("last_synced_at").toInstant() : null,
			rs.getString("status"),
			rs.getInt("prefix_count"),
			rs.getString("last_error")
	);

	public List<CrawlerFeed> findAll() {
		return jdbcTemplate.query("SELECT * FROM crawler_feeds ORDER BY name ASC", ROW_MAPPER);
	}

	public Optional<CrawlerFeed> findByKey(String feedKey) {
		List<CrawlerFeed> list = jdbcTemplate.query(
				"SELECT * FROM crawler_feeds WHERE feed_key = ?", ROW_MAPPER, feedKey);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	public void upsert(CrawlerFeed feed) {
		String sql = """
				INSERT INTO crawler_feeds (feed_key, name, category, url, last_synced_at, status, prefix_count, last_error)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (feed_key) DO UPDATE SET
				    name = EXCLUDED.name,
				    category = EXCLUDED.category,
				    url = EXCLUDED.url
				""";
		Timestamp syncedTs = feed.lastSyncedAt() != null ? Timestamp.from(feed.lastSyncedAt()) : null;
		jdbcTemplate.update(sql,
				feed.feedKey(),
				feed.name(),
				feed.category(),
				feed.url(),
				syncedTs,
				feed.status() != null ? feed.status() : "PENDING",
				feed.prefixCount(),
				feed.lastError()
		);
	}

	public void updateSyncStatus(String feedKey, String status, int prefixCount, String lastError, Instant lastSyncedAt) {
		String sql = """
				UPDATE crawler_feeds SET
				    status = ?,
				    prefix_count = ?,
				    last_error = ?,
				    last_synced_at = ?
				WHERE feed_key = ?
				""";
		Timestamp ts = lastSyncedAt != null ? Timestamp.from(lastSyncedAt) : Timestamp.from(Instant.now());
		jdbcTemplate.update(sql, status, prefixCount, lastError, ts, feedKey);
	}

	public int deleteNotIn(List<String> activeKeys) {
		if (activeKeys == null || activeKeys.isEmpty()) {
			return jdbcTemplate.update("DELETE FROM crawler_feeds");
		}
		StringBuilder sql = new StringBuilder("DELETE FROM crawler_feeds WHERE feed_key NOT IN (");
		for (int i = 0; i < activeKeys.size(); i++) {
			sql.append(i > 0 ? ",?" : "?");
		}
		sql.append(")");
		return jdbcTemplate.update(sql.toString(), activeKeys.toArray());
	}
}
