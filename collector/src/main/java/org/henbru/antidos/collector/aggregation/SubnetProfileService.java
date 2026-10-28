package org.henbru.antidos.collector.aggregation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.SubnetProfile;
import org.henbru.antidos.collector.storage.SubnetProfileRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service orchestrating subnet profile baseline calculation, dormancy tracking,
 * and surge anomaly detection.
 */
@Service
public class SubnetProfileService {

	private static final Logger log = LoggerFactory.getLogger(SubnetProfileService.class);

	private final SubnetProfileRepository profileRepository;
	private final CollectorProperties properties;
	private final org.henbru.antidos.collector.storage.SubnetRollupRepository rollupRepository;
	private final org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository;

	@Autowired
	public SubnetProfileService(
			SubnetProfileRepository profileRepository,
			CollectorProperties properties,
			@Autowired(required = false) org.henbru.antidos.collector.storage.SubnetRollupRepository rollupRepository,
			@Autowired(required = false) org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository) {
		this.profileRepository = profileRepository;
		this.properties = properties;
		this.rollupRepository = rollupRepository;
		this.clientEventRepository = clientEventRepository;
	}

	public SubnetProfileService(SubnetProfileRepository profileRepository, CollectorProperties properties) {
		this(profileRepository, properties, null, null);
	}

	public SubnetProfileService(SubnetProfileRepository profileRepository) {
		this(profileRepository, new CollectorProperties(), null, null);
	}

	/**
	 * Refreshes all subnet profiles by re-computing 24h burst and 30-day baseline statistics from historical rollups.
	 *
	 * @return number of profiles updated
	 */
	public int refreshProfiles() {
		if (!properties.isRollupEnabled()) {
			return 0;
		}

		long start = System.currentTimeMillis();
		Instant now = Instant.now();
		Instant cutoff24h = now.minus(24, ChronoUnit.HOURS);
		Instant cutoff30d = now.minus(30, ChronoUnit.DAYS);

		try {
			List<SubnetProfile> profiles = profileRepository.computeProfilesFromRollups(cutoff24h, cutoff30d);
			if (!profiles.isEmpty()) {
				profileRepository.batchUpsert(profiles);
			}
			long duration = System.currentTimeMillis() - start;
			log.info("Refreshed {} subnet profiles (baselines & 24h surge) in {}ms", profiles.size(), duration);
			return profiles.size();
		} catch (Exception e) {
			log.error("Failed to refresh subnet profiles: {}", e.getMessage(), e);
			return 0;
		}
	}

	public List<SubnetProfile> findProfilesFiltered(
			String activityPattern,
			Long minRequests24h,
			String subnetQuery,
			Long asn,
			String asOrg,
			List<String> clientTypes,
			String sortBy,
			int limit,
			int offset
	) {
		return profileRepository.findProfilesFiltered(
				activityPattern, minRequests24h, subnetQuery, asn, asOrg, clientTypes, sortBy, limit, offset);
	}

	public long countProfilesFiltered(
			String activityPattern,
			Long minRequests24h,
			String subnetQuery,
			Long asn,
			String asOrg,
			List<String> clientTypes
	) {
		return profileRepository.countProfilesFiltered(
				activityPattern, minRequests24h, subnetQuery, asn, asOrg, clientTypes);
	}

	public Optional<SubnetProfile> findBySubnetGroup(String subnetGroup) {
		return profileRepository.findBySubnetGroup(subnetGroup);
	}

	public Map<String, SubnetProfile> findSubnetProfilesMap(List<String> subnetGroups) {
		return profileRepository.findSubnetProfilesMap(subnetGroups);
	}

	public org.henbru.antidos.collector.model.SubnetProfileStats getProfileStats() {
		return profileRepository.getProfileStats();
	}

	public org.henbru.antidos.collector.model.SubnetProfileFreshness getProfileFreshness() {
		Instant latestRollupEnd = (rollupRepository != null)
				? rollupRepository.findLatestBucketEnd().orElse(null)
				: null;
		Instant earliestRollupStart = (rollupRepository != null)
				? rollupRepository.findEarliestBucketStart().orElse(null)
				: null;
		Instant latestEventTime = (clientEventRepository != null)
				? clientEventRepository.findLatestSlotTime().orElse(null)
				: null;
		Instant lastUpdated = profileRepository.findLatestUpdatedAt().orElse(null);
		int windowMinutes = properties != null ? properties.getRollupWindowMinutes() : 60;

		return org.henbru.antidos.collector.model.SubnetProfileFreshness.of(
				latestRollupEnd,
				latestEventTime,
				earliestRollupStart,
				lastUpdated,
				windowMinutes
		);
	}
}

