package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EnrichmentStatus;
import org.henbru.antidos.collector.model.NetworkEntity;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing and querying normalized network intelligence entities (IPs and subnets).
 */
@Repository
public class NetworkEntityRepository {

	private final JdbcTemplate jdbcTemplate;

	public NetworkEntityRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<NetworkEntity> ROW_MAPPER = (rs, rowNum) -> {
		Long v4Start = rs.getObject("ip_v4_start") != null ? rs.getLong("ip_v4_start") : null;
		Long v4End = rs.getObject("ip_v4_end") != null ? rs.getLong("ip_v4_end") : null;
		Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
		String rawClientType = rs.getString("client_type");
		ClientType clientType = rawClientType != null ? ClientType.valueOf(rawClientType) : ClientType.UNKNOWN;
		String rawStatus = rs.getString("enrichment_status");
		EnrichmentStatus enrichmentStatus = rawStatus != null ? EnrichmentStatus.valueOf(rawStatus) : EnrichmentStatus.PENDING;
		Timestamp resolvedTs = rs.getTimestamp("resolved_at");
		Timestamp firstSeenTs = rs.getTimestamp("first_seen");
		Timestamp lastSeenTs = rs.getTimestamp("last_seen");

		return new NetworkEntity(
				rs.getLong("id"),
				rs.getString("client_key"),
				rs.getInt("ip_version"),
				rs.getInt("cidr_prefix"),
				v4Start,
				v4End,
				rs.getString("ip_v6_start"),
				rs.getString("ip_v6_end"),
				rs.getString("subnet_group"),
				rs.getString("mmdb_network"),
				asn,
				rs.getString("as_org"),
				rs.getString("country_code"),
				clientType,
				rs.getString("tags"),
				enrichmentStatus,
				resolvedTs != null ? resolvedTs.toInstant() : null,
				rs.getString("resolved_versions"),
				firstSeenTs != null ? firstSeenTs.toInstant() : null,
				lastSeenTs != null ? lastSeenTs.toInstant() : null
		);
	};

	public Optional<NetworkEntity> findByClientKey(String clientKey) {
		if (clientKey == null || clientKey.trim().isEmpty()) {
			return Optional.empty();
		}
		List<NetworkEntity> list = jdbcTemplate.query(
				"SELECT * FROM network_entity WHERE client_key = ? LIMIT 1",
				ROW_MAPPER, clientKey.trim());
		return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	public Optional<NetworkEntity> findById(long id) {
		List<NetworkEntity> list = jdbcTemplate.query(
				"SELECT * FROM network_entity WHERE id = ? LIMIT 1",
				ROW_MAPPER, id);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
	}

	public void batchUpsert(List<NetworkEntity> entities) {
		if (entities == null || entities.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO network_entity (
				    client_key, ip_version, cidr_prefix, ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end, subnet_group,
				    mmdb_network, asn, as_org, country_code, client_type, tags, enrichment_status,
				    resolved_at, resolved_versions, first_seen, last_seen
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (client_key) DO UPDATE SET
				    ip_version = EXCLUDED.ip_version,
				    cidr_prefix = EXCLUDED.cidr_prefix,
				    ip_v4_start = EXCLUDED.ip_v4_start,
				    ip_v4_end = EXCLUDED.ip_v4_end,
				    ip_v6_start = EXCLUDED.ip_v6_start,
				    ip_v6_end = EXCLUDED.ip_v6_end,
				    subnet_group = EXCLUDED.subnet_group,
				    last_seen = EXCLUDED.last_seen
				""";

		StorageRetryUtil.executeWithRetry("NetworkEntityRepository.batchUpsert", () -> {
			jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
				@Override
				public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
					NetworkEntity e = entities.get(i);
					ps.setString(1, e.clientKey());
					ps.setInt(2, e.ipVersion());
					ps.setInt(3, e.cidrPrefix());
					if (e.ipV4Start() != null) {
						ps.setLong(4, e.ipV4Start());
					} else {
						ps.setNull(4, Types.BIGINT);
					}
					if (e.ipV4End() != null) {
						ps.setLong(5, e.ipV4End());
					} else {
						ps.setNull(5, Types.BIGINT);
					}
					ps.setString(6, e.ipV6Start());
					ps.setString(7, e.ipV6End());
					ps.setString(8, e.subnetGroup());
					ps.setString(9, e.mmdbNetwork());
					if (e.asn() != null) {
						ps.setLong(10, e.asn());
					} else {
						ps.setNull(10, Types.BIGINT);
					}
					ps.setString(11, e.asOrg());
					ps.setString(12, e.countryCode());
					ps.setString(13, e.clientType() != null ? e.clientType().name() : ClientType.UNKNOWN.name());
					ps.setString(14, e.tags());
					ps.setString(15, e.enrichmentStatus() != null ? e.enrichmentStatus().name() : EnrichmentStatus.PENDING.name());
					ps.setTimestamp(16, e.resolvedAt() != null ? Timestamp.from(e.resolvedAt()) : null);
					ps.setString(17, e.resolvedVersions());
					ps.setTimestamp(18, e.firstSeen() != null ? Timestamp.from(e.firstSeen()) : new Timestamp(System.currentTimeMillis()));
					ps.setTimestamp(19, e.lastSeen() != null ? Timestamp.from(e.lastSeen()) : new Timestamp(System.currentTimeMillis()));
				}

				@Override
				public int getBatchSize() {
					return entities.size();
				}
			});
		});
	}

	public List<NetworkEntity> findPendingEnrichment(int limit) {
		String sql = "SELECT * FROM network_entity WHERE enrichment_status = 'PENDING' ORDER BY id ASC LIMIT ?";
		return jdbcTemplate.query(sql, ROW_MAPPER, limit);
	}

	public void batchUpdateEnrichment(List<NetworkEntity> entities) {
		if (entities == null || entities.isEmpty()) {
			return;
		}

		String sql = """
				UPDATE network_entity SET
				    mmdb_network = ?,
				    asn = ?,
				    as_org = ?,
				    country_code = ?,
				    client_type = ?,
				    tags = ?,
				    enrichment_status = ?,
				    resolved_at = ?,
				    resolved_versions = ?
				WHERE id = ?
				""";

		StorageRetryUtil.executeWithRetry("NetworkEntityRepository.batchUpdateEnrichment", () -> {
			jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
				@Override
				public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
					NetworkEntity e = entities.get(i);
					ps.setString(1, e.mmdbNetwork());
					if (e.asn() != null) {
						ps.setLong(2, e.asn());
					} else {
						ps.setNull(2, Types.BIGINT);
					}
					ps.setString(3, e.asOrg());
					ps.setString(4, e.countryCode());
					ps.setString(5, e.clientType() != null ? e.clientType().name() : ClientType.UNKNOWN.name());
					ps.setString(6, e.tags());
					ps.setString(7, e.enrichmentStatus() != null ? e.enrichmentStatus().name() : EnrichmentStatus.ENRICHED.name());
					ps.setTimestamp(8, e.resolvedAt() != null ? Timestamp.from(e.resolvedAt()) : new Timestamp(System.currentTimeMillis()));
					ps.setString(9, e.resolvedVersions());
					ps.setLong(10, e.id());
				}

				@Override
				public int getBatchSize() {
					return entities.size();
				}
			});
		});
	}

	public void updateTags(long entityId, String tags) {
		String sql = "UPDATE network_entity SET tags = ? WHERE id = ?";
		StorageRetryUtil.executeWithRetry("NetworkEntityRepository.updateTags", () -> {
			jdbcTemplate.update(sql, tags, entityId);
		});
	}

	public long count() {
		Long count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM network_entity", Long.class);
		return count != null ? count : 0L;
	}

	/**
	 * Deletes inactive network entities that have not been seen since lastSeenBefore
	 * and are no longer referenced by any blocked client events.
	 * Also cleans up any associated network_entity_match records.
	 *
	 * @param lastSeenBefore cut-off timestamp for inactive entities
	 * @return number of deleted entities
	 */
	public int deleteOrphans(Instant lastSeenBefore) {
		if (lastSeenBefore == null) {
			return 0;
		}
		Timestamp ts = Timestamp.from(lastSeenBefore);
		String deleteMatchesSql = """
				DELETE FROM network_entity_match
				WHERE entity_id IN (
				    SELECT id FROM network_entity
				    WHERE last_seen < ?
				      AND NOT EXISTS (
				          SELECT 1 FROM client_events b WHERE b.entity_id = network_entity.id
				      )
				)
				""";
		jdbcTemplate.update(deleteMatchesSql, ts);

		String deleteEntitiesSql = """
				DELETE FROM network_entity
				WHERE last_seen < ?
				  AND NOT EXISTS (
				      SELECT 1 FROM client_events b WHERE b.entity_id = network_entity.id
				  )
				""";
		return jdbcTemplate.update(deleteEntitiesSql, ts);
	}

	/**
	 * Marks enriched entities resolved before the specified cutoff as PENDING
	 * so that the background enrichment worker refreshes their metadata against
	 * updated GeoIP MMDB and intelligence feeds (e.g. 30-day MaxMind GeoLite2 compliance).
	 * Private network entities are excluded because RFC1918 / ULA ranges never expire.
	 *
	 * @param resolvedBefore cut-off timestamp
	 * @return number of entities marked as PENDING
	 */
	public int markExpiredEnrichment(Instant resolvedBefore) {
		if (resolvedBefore == null) {
			return 0;
		}
		String sql = """
				UPDATE network_entity
				SET enrichment_status = 'PENDING'
				WHERE enrichment_status = 'ENRICHED'
				  AND client_type != 'PRIVATE_NETWORK'
				  AND resolved_at < ?
				""";
		return jdbcTemplate.update(sql, Timestamp.from(resolvedBefore));
	}

	/**
	 * Marks an individual entity as PENDING for immediate re-enrichment.
	 */
	public void markPending(Long entityId) {
		if (entityId == null) {
			return;
		}
		jdbcTemplate.update("UPDATE network_entity SET enrichment_status = 'PENDING' WHERE id = ?", entityId);
	}
}
