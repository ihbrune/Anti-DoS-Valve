package org.henbru.antidos.collector.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * DTO representing the overview JSON payload from an AntiDoSValve status endpoint.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ValveOverviewDto(
		String serverTime,
		List<ValveSummaryDto> valves,
		String error
) {
	@JsonIgnoreProperties(ignoreUnknown = true)
	public record ValveSummaryDto(
			String monitorName,
			int pipelineOrder,
			String monitorMode,
			boolean simulationMode,
			boolean serverWideBlocking,
			int allowedRequestsPerSlot,
			int slotLength,
			int numberOfSlots,
			int currentActiveCounters,
			int currentBlockedCounters,
			long currentSlotKey,
			long lastCompletedSlotKey,
			long totalRequests,
			long previousTotalRequests,
			int previousActiveCounters,
			int previousBlockedCounters
	) {
	}
}
