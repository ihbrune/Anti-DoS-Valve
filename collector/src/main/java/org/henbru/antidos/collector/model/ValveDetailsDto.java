package org.henbru.antidos.collector.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * DTO representing the details JSON payload from an AntiDoSValve status endpoint.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ValveDetailsDto(
		String serverTime,
		ValveHeaderDto valve,
		SelectedSlotDto selectedSlot,
		int totalBlockedClients,
		String blockedLimit,
		Long maxBlockedOrder,
		Long sinceBlockedOrder,
		List<BlockedClientDto> blockedClients,
		int totalActiveClients,
		String activeLimit,
		Long maxActiveOrder,
		Long sinceActiveOrder,
		Integer activeMinCount,
		List<ActiveClientDto> topActiveClients,
		String error
) {
	/**
	 * Backward-compatible constructor for previous 7-parameter signature.
	 */
	public ValveDetailsDto(String serverTime, ValveHeaderDto valve, SelectedSlotDto selectedSlot,
			int totalBlockedClients, String blockedLimit, List<BlockedClientDto> blockedClients, String error) {
		this(serverTime, valve, selectedSlot, totalBlockedClients, blockedLimit, null, null,
				blockedClients, 0, null, null, null, null, null, error);
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record ValveHeaderDto(
			String monitorName,
			long currentSlotKey,
			long lastCompletedSlotKey,
			int slotLength,
			int numberOfSlots,
			Boolean visitorCookieEnabled
	) {
		public ValveHeaderDto(String monitorName, long currentSlotKey, long lastCompletedSlotKey, int slotLength, int numberOfSlots) {
			this(monitorName, currentSlotKey, lastCompletedSlotKey, slotLength, numberOfSlots, null);
		}
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record SelectedSlotDto(
			String type,
			Integer index,
			long slotKey,
			boolean isCurrent,
			String startTime,
			String endTime,
			long totalRequests,
			int activeCounters,
			int blockedCounters
	) {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record BlockedClientDto(
			String key,
			int count,
			int retained,
			int effective,
			boolean locked,
			String lastUpdate,
			Integer distinctClients,
			Integer returningCount,
			Integer authenticatedCount,
			String sampleMethod,
			String sampleUri,
			String sampleUserAgent
	) {
		public BlockedClientDto(
				String key,
				int count,
				int retained,
				int effective,
				boolean locked,
				String lastUpdate,
				Integer distinctClients,
				Integer returningCount,
				Integer authenticatedCount
		) {
			this(key, count, retained, effective, locked, lastUpdate, distinctClients, returningCount, authenticatedCount, null, null, null);
		}

		public BlockedClientDto(String key, int count, int retained, int effective, boolean locked, String lastUpdate, Integer distinctClients) {
			this(key, count, retained, effective, locked, lastUpdate, distinctClients, null, null, null, null, null);
		}

		public BlockedClientDto(String key, int count, int retained, int effective, boolean locked, String lastUpdate) {
			this(key, count, retained, effective, locked, lastUpdate, 1, null, null, null, null, null);
		}

		public BlockedClientDto(String key, int count, int retained, boolean locked, String lastUpdate) {
			this(key, count, retained, count + retained, locked, lastUpdate, 1, null, null, null, null, null);
		}
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record ActiveClientDto(
			String key,
			int count,
			int retained,
			int effective,
			int limit,
			int quotaPercent,
			Integer distinctClients,
			Integer returningCount,
			Integer authenticatedCount
	) {
		public ActiveClientDto(String key, int count, int retained, int effective, int limit, int quotaPercent, Integer distinctClients) {
			this(key, count, retained, effective, limit, quotaPercent, distinctClients, null, null);
		}

		public ActiveClientDto(String key, int count, int retained, int effective, int limit, int quotaPercent) {
			this(key, count, retained, effective, limit, quotaPercent, 1, null, null);
		}
	}
}
