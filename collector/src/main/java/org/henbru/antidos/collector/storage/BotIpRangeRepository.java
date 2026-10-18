package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.model.BotIpRange;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * JDBC repository for storing and querying verified bot and crawler IP CIDR ranges.
 */
@Repository
@SuppressWarnings("null")
public class BotIpRangeRepository {

	public record BotMatch(String feedKey, String botName, String category) {
	}

	private final JdbcTemplate jdbcTemplate;

	public BotIpRangeRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@Transactional
	public void replaceRangesForFeed(String feedKey, List<BotIpRange> ranges) {
		jdbcTemplate.update("DELETE FROM bot_ip_ranges WHERE feed_key = ?", feedKey);
		if (ranges == null || ranges.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO bot_ip_ranges (feed_key, cidr, ip_version, ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end)
				VALUES (?, ?, ?, ?, ?, ?, ?)
				""";

		jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
			@Override
			public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
				BotIpRange r = ranges.get(i);
				ps.setString(1, feedKey);
				ps.setString(2, r.cidr());
				ps.setInt(3, r.ipVersion());
				if (r.ipV4Start() != null) {
					ps.setLong(4, r.ipV4Start());
				} else {
					ps.setNull(4, Types.BIGINT);
				}
				if (r.ipV4End() != null) {
					ps.setLong(5, r.ipV4End());
				} else {
					ps.setNull(5, Types.BIGINT);
				}
				ps.setString(6, r.ipV6Start());
				ps.setString(7, r.ipV6End());
			}

			@Override
			public int getBatchSize() {
				return ranges.size();
			}
		});
	}

	public int deleteNotInFeedKeys(List<String> activeKeys) {
		if (activeKeys == null || activeKeys.isEmpty()) {
			return jdbcTemplate.update("DELETE FROM bot_ip_ranges");
		}
		StringBuilder sql = new StringBuilder("DELETE FROM bot_ip_ranges WHERE feed_key NOT IN (");
		for (int i = 0; i < activeKeys.size(); i++) {
			sql.append(i > 0 ? ",?" : "?");
		}
		sql.append(")");
		return jdbcTemplate.update(sql.toString(), activeKeys.toArray());
	}

	public Optional<BotMatch> findBotForIp(String ipOrClientKey) {
		if (ipOrClientKey == null || ipOrClientKey.trim().isEmpty()) {
			return Optional.empty();
		}
		IpNetworkInfo net = IpNetworkUtil.parse(ipOrClientKey);
		if (net.version() == 4 && net.v4Start() != null) {
			String sql = """
					SELECT r.feed_key, f.name, f.category
					FROM bot_ip_ranges r
					JOIN crawler_feeds f ON r.feed_key = f.feed_key
					WHERE r.ip_version = 4 AND r.ip_v4_start <= ? AND r.ip_v4_end >= ?
					LIMIT 1
					""";
			List<BotMatch> matches = jdbcTemplate.query(sql, (rs, rowNum) -> new BotMatch(
					rs.getString("feed_key"),
					rs.getString("name"),
					rs.getString("category")
			), net.v4Start(), net.v4Start());
			return matches.isEmpty() ? Optional.empty() : Optional.of(matches.get(0));
		} else if (net.version() == 6 && net.v6Start() != null) {
			String sql = """
					SELECT r.feed_key, f.name, f.category
					FROM bot_ip_ranges r
					JOIN crawler_feeds f ON r.feed_key = f.feed_key
					WHERE r.ip_version = 6 AND r.ip_v6_start <= ? AND r.ip_v6_end >= ?
					LIMIT 1
					""";
			List<BotMatch> matches = jdbcTemplate.query(sql, (rs, rowNum) -> new BotMatch(
					rs.getString("feed_key"),
					rs.getString("name"),
					rs.getString("category")
			), net.v6Start(), net.v6Start());
			return matches.isEmpty() ? Optional.empty() : Optional.of(matches.get(0));
		}
		return Optional.empty();
	}

	public int countRangesByFeedKey(String feedKey) {
		Integer count = jdbcTemplate.queryForObject(
				"SELECT COUNT(*) FROM bot_ip_ranges WHERE feed_key = ?", Integer.class, feedKey);
		return count != null ? count : 0;
	}
}
