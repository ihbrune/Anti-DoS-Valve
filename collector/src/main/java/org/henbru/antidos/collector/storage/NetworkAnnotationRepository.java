package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.model.AnnotationTargetType;
import org.henbru.antidos.collector.model.AnnotationVerdict;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing, updating, and querying persistent network annotations.
 * Note: Data in this repository is independent and never pruned by data retention cleanup.
 */
@Repository
public class NetworkAnnotationRepository {

	private final JdbcTemplate jdbcTemplate;

	public NetworkAnnotationRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<NetworkAnnotation> ROW_MAPPER = (rs, rowNum) -> {
		Long id = rs.getLong("id");
		String rawTargetType = rs.getString("target_type");
		AnnotationTargetType targetType = rawTargetType != null ? AnnotationTargetType.valueOf(rawTargetType) : AnnotationTargetType.ASN;
		String targetKey = rs.getString("target_key");
		Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
		String subnetGroup = rs.getString("subnet_group");
		int ipVersion = rs.getInt("ip_version");
		int cidrPrefix = rs.getInt("cidr_prefix");
		Long v4Start = rs.getObject("ip_v4_start") != null ? rs.getLong("ip_v4_start") : null;
		Long v4End = rs.getObject("ip_v4_end") != null ? rs.getLong("ip_v4_end") : null;
		String v6Start = rs.getString("ip_v6_start");
		String v6End = rs.getString("ip_v6_end");
		String rawVerdict = rs.getString("verdict");
		AnnotationVerdict verdict = rawVerdict != null ? AnnotationVerdict.valueOf(rawVerdict) : AnnotationVerdict.INFO;
		String noteMarkdown = rs.getString("note_markdown");
		Timestamp createdAtTs = rs.getTimestamp("created_at");
		Timestamp updatedAtTs = rs.getTimestamp("updated_at");

		return new NetworkAnnotation(
				id,
				targetType,
				targetKey,
				asn,
				subnetGroup,
				ipVersion,
				cidrPrefix,
				v4Start,
				v4End,
				v6Start,
				v6End,
				verdict,
				noteMarkdown,
				createdAtTs != null ? createdAtTs.toInstant() : Instant.now(),
				updatedAtTs != null ? updatedAtTs.toInstant() : Instant.now()
		);
	};

	public void upsert(NetworkAnnotation a) {
		String sql = """
				INSERT INTO network_annotations (
				    target_type, target_key, asn, subnet_group, ip_version, cidr_prefix,
				    ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end, verdict, note_markdown,
				    created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (target_type, target_key) DO UPDATE SET
				    asn = EXCLUDED.asn,
				    subnet_group = EXCLUDED.subnet_group,
				    ip_version = EXCLUDED.ip_version,
				    cidr_prefix = EXCLUDED.cidr_prefix,
				    ip_v4_start = EXCLUDED.ip_v4_start,
				    ip_v4_end = EXCLUDED.ip_v4_end,
				    ip_v6_start = EXCLUDED.ip_v6_start,
				    ip_v6_end = EXCLUDED.ip_v6_end,
				    verdict = EXCLUDED.verdict,
				    note_markdown = EXCLUDED.note_markdown,
				    updated_at = EXCLUDED.updated_at
				""";

		Instant now = Instant.now();
		Instant created = a.createdAt() != null ? a.createdAt() : now;
		Instant updated = a.updatedAt() != null ? a.updatedAt() : now;

		jdbcTemplate.update(sql, ps -> {
			ps.setString(1, a.targetType().name());
			ps.setString(2, a.targetKey());
			if (a.asn() != null) {
				ps.setLong(3, a.asn());
			} else {
				ps.setNull(3, Types.BIGINT);
			}
			ps.setString(4, a.subnetGroup());
			ps.setInt(5, a.ipVersion());
			ps.setInt(6, a.cidrPrefix());
			if (a.ipV4Start() != null) {
				ps.setLong(7, a.ipV4Start());
			} else {
				ps.setNull(7, Types.BIGINT);
			}
			if (a.ipV4End() != null) {
				ps.setLong(8, a.ipV4End());
			} else {
				ps.setNull(8, Types.BIGINT);
			}
			ps.setString(9, a.ipV6Start());
			ps.setString(10, a.ipV6End());
			ps.setString(11, a.verdict().name());
			ps.setString(12, a.noteMarkdown());
			ps.setTimestamp(13, Timestamp.from(created));
			ps.setTimestamp(14, Timestamp.from(updated));
		});
	}

	public Optional<NetworkAnnotation> findById(long id) {
		List<NetworkAnnotation> list = jdbcTemplate.query(
				"SELECT * FROM network_annotations WHERE id = ? LIMIT 1",
				ROW_MAPPER, id);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	public Optional<NetworkAnnotation> findByTarget(AnnotationTargetType targetType, String targetKey) {
		if (targetType == null || targetKey == null || targetKey.isBlank()) {
			return Optional.empty();
		}
		List<NetworkAnnotation> list = jdbcTemplate.query(
				"SELECT * FROM network_annotations WHERE target_type = ? AND target_key = ? LIMIT 1",
				ROW_MAPPER, targetType.name(), targetKey.trim());
		return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	public Optional<NetworkAnnotation> findByAsn(long asn) {
		List<NetworkAnnotation> list = jdbcTemplate.query(
				"SELECT * FROM network_annotations WHERE target_type = 'ASN' AND asn = ? LIMIT 1",
				ROW_MAPPER, asn);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	public Optional<NetworkAnnotation> findBySubnet(String subnetGroup) {
		if (subnetGroup == null || subnetGroup.isBlank()) {
			return Optional.empty();
		}
		List<NetworkAnnotation> list = jdbcTemplate.query(
				"SELECT * FROM network_annotations WHERE target_type = 'SUBNET' AND (subnet_group = ? OR target_key = ?) LIMIT 1",
				ROW_MAPPER, subnetGroup.trim(), subnetGroup.trim());
		return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	public List<NetworkAnnotation> findAll(String sortBy) {
		String orderClause = resolveOrderClause(sortBy);
		return jdbcTemplate.query("SELECT * FROM network_annotations ORDER BY " + orderClause, ROW_MAPPER);
	}

	public List<NetworkAnnotation> findFiltered(AnnotationTargetType targetType, AnnotationVerdict verdict, String query, String sortBy) {
		StringBuilder sql = new StringBuilder("SELECT * FROM network_annotations WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		if (targetType != null) {
			sql.append("AND target_type = ? ");
			params.add(targetType.name());
		}

		if (verdict != null) {
			sql.append("AND verdict = ? ");
			params.add(verdict.name());
		}

		if (query != null && !query.isBlank()) {
			String q = "%" + query.trim().toLowerCase() + "%";
			sql.append("AND (LOWER(target_key) LIKE ? OR LOWER(note_markdown) LIKE ? OR CAST(asn AS TEXT) LIKE ?) ");
			params.add(q);
			params.add(q);
			params.add(q);
		}

		sql.append("ORDER BY ").append(resolveOrderClause(sortBy));

		return jdbcTemplate.query(sql.toString(), ROW_MAPPER, params.toArray());
	}

	public boolean deleteById(long id) {
		return jdbcTemplate.update("DELETE FROM network_annotations WHERE id = ?", id) > 0;
	}

	public boolean deleteByTarget(AnnotationTargetType targetType, String targetKey) {
		if (targetType == null || targetKey == null) {
			return false;
		}
		return jdbcTemplate.update(
				"DELETE FROM network_annotations WHERE target_type = ? AND target_key = ?",
				targetType.name(), targetKey.trim()) > 0;
	}

	public long count() {
		Long c = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM network_annotations", Long.class);
		return c != null ? c : 0L;
	}

	public Map<AnnotationVerdict, Long> countByVerdict() {
		Map<AnnotationVerdict, Long> map = new EnumMap<>(AnnotationVerdict.class);
		for (AnnotationVerdict v : AnnotationVerdict.values()) {
			map.put(v, 0L);
		}
		String sql = "SELECT verdict, COUNT(*) as cnt FROM network_annotations GROUP BY verdict";
		jdbcTemplate.query(sql, rs -> {
			String vStr = rs.getString("verdict");
			long cnt = rs.getLong("cnt");
			try {
				AnnotationVerdict v = AnnotationVerdict.valueOf(vStr);
				map.put(v, cnt);
			} catch (IllegalArgumentException ignored) {
			}
		});
		return map;
	}

	private String resolveOrderClause(String sortBy) {
		if (sortBy == null) {
			return "updated_at DESC";
		}
		return switch (sortBy.trim().toLowerCase()) {
			case "created_asc" -> "created_at ASC";
			case "created_desc" -> "created_at DESC";
			case "updated_asc" -> "updated_at ASC";
			case "target" -> "target_key ASC";
			case "verdict" -> "verdict ASC, updated_at DESC";
			default -> "updated_at DESC";
		};
	}
}
