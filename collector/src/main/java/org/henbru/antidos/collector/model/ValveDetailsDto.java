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
		List<BlockedClientDto> blockedClients,
		String error
) {
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
			boolean locked,
			String lastUpdate
	) {
	}
}
