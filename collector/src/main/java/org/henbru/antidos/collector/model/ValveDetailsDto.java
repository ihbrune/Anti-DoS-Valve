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
			int numberOfSlots
	) {
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
			String lastUpdate
	) {
		/**
		 * Backward-compatible constructor for previous 5-parameter signature.
		 */
		public BlockedClientDto(String key, int count, int retained, boolean locked, String lastUpdate) {
			this(key, count, retained, count + retained, locked, lastUpdate);
		}
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record ActiveClientDto(
			String key,
			int count,
			int retained,
			int effective,
			int limit,
			int quotaPercent
	) {
	}
}
