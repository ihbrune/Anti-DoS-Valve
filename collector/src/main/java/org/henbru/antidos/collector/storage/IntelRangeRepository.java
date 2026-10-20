package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.List;
import org.henbru.antidos.collector.model.IntelRange;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * JDBC repository for storing and querying individual CIDR ranges from intelligence sources.
 */
@Repository
@SuppressWarnings("null")
public class IntelRangeRepository {

	private final JdbcTemplate jdbcTemplate;

	public IntelRangeRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<IntelRange> ROW_MAPPER = (rs, rowNum) -> {
		Long v4Start = rs.getObject("ip_v4_start") != null ? rs.getLong("ip_v4_start") : null;
		Long v4End = rs.getObject("ip_v4_end") != null ? rs.getLong("ip_v4_end") : null;
		Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
		Timestamp createdTs = rs.getTimestamp("created_at");

		return new IntelRange(
				rs.getLong("id"),
				rs.getString("source_key"),
				rs.getString("cidr"),
				rs.getInt("ip_version"),
				rs.getInt("cidr_prefix"),
				v4Start,
				v4End,
				rs.getString("ip_v6_start"),
				rs.getString("ip_v6_end"),
				asn,
				rs.getString("country_code"),
				rs.getString("category"),
				rs.getString("label"),
				rs.getLong("source_version"),
				createdTs != null ? createdTs.toInstant() : null
		);
	};

	@Transactional
	public void replaceRangesForSource(String sourceKey, List<IntelRange> ranges) {
		jdbcTemplate.update("DELETE FROM intel_range WHERE source_key = ?", sourceKey);
		if (ranges == null || ranges.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO intel_range (
				    source_key, cidr, ip_version, cidr_prefix, ip_v4_start, ip_v4_end,
				    ip_v6_start, ip_v6_end, asn, country_code, category, label, source_version
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				""";

		jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
			@Override
			public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
				IntelRange r = ranges.get(i);
				ps.setString(1, sourceKey);
				ps.setString(2, r.cidr());
				ps.setInt(3, r.ipVersion());
				ps.setInt(4, r.cidrPrefix());
				if (r.ipV4Start() != null) {
					ps.setLong(5, r.ipV4Start());
				} else {
					ps.setNull(5, Types.BIGINT);
				}
				if (r.ipV4End() != null) {
					ps.setLong(6, r.ipV4End());
				} else {
					ps.setNull(6, Types.BIGINT);
				}
				ps.setString(7, r.ipV6Start());
				ps.setString(8, r.ipV6End());
				if (r.asn() != null) {
					ps.setLong(9, r.asn());
				} else {
					ps.setNull(9, Types.BIGINT);
				}
				ps.setString(10, r.countryCode());
				ps.setString(11, r.category());
				ps.setString(12, r.label());
				ps.setLong(13, r.sourceVersion());
			}

			@Override
			public int getBatchSize() {
				return ranges.size();
			}
		});
	}

	public List<IntelRange> findAll() {
		return jdbcTemplate.query("SELECT * FROM intel_range ORDER BY id ASC", ROW_MAPPER);
	}

	public int deleteNotInSourceKeys(List<String> activeKeys) {
		if (activeKeys == null || activeKeys.isEmpty()) {
			return jdbcTemplate.update("DELETE FROM intel_range");
		}
		StringBuilder sql = new StringBuilder("DELETE FROM intel_range WHERE source_key NOT IN (");
		for (int i = 0; i < activeKeys.size(); i++) {
			sql.append(i > 0 ? ",?" : "?");
		}
		sql.append(")");
		return jdbcTemplate.update(sql.toString(), activeKeys.toArray());
	}

	public int countRangesBySourceKey(String sourceKey) {
		Integer count = jdbcTemplate.queryForObject(
				"SELECT COUNT(*) FROM intel_range WHERE source_key = ?", Integer.class, sourceKey);
		return count != null ? count : 0;
	}
}
