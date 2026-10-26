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
			String description,
			int pipelineOrder,
			String monitorMode,
			boolean simulationMode,
			boolean serverWideBlocking,
			int httpStatusCode,
			int allowedRequestsPerSlot,
			int slotLength,
			int numberOfSlots,
			float shareOfRetainedFormerRequests,
			int ipv4SubnetMask,
			int ipv6SubnetMask,
			int maxIPCacheSize,
			int maxBlockedIPCacheSize,
			String relevantPaths,
			String nonRelevantPaths,
			String alwaysAllowedIPs,
			String alwaysForbiddenIPs,
			String statusUri,
			String statusAllowedIPs,
			String collectorIntegration,
			boolean visitorCookieEnabled,
			String visitorCookieName,
			long alwaysForbiddenBlockedRequests,
			int currentActiveCounters,
			int currentBlockedCounters,
			long currentSlotKey,
			long lastCompletedSlotKey,
			long totalRequests,
			long previousTotalRequests,
			int previousActiveCounters,
			int previousBlockedCounters,
			int activeSlots,
			boolean isStatusHost,
			boolean isCurrentHost
	) {
		/**
		 * Overloaded constructor without visitorCookieEnabled / visitorCookieName for backwards compatibility.
		 */
		public ValveSummaryDto(
				String monitorName,
				String description,
				int pipelineOrder,
				String monitorMode,
				boolean simulationMode,
				boolean serverWideBlocking,
				int httpStatusCode,
				int allowedRequestsPerSlot,
				int slotLength,
				int numberOfSlots,
				float shareOfRetainedFormerRequests,
				int ipv4SubnetMask,
				int ipv6SubnetMask,
				int maxIPCacheSize,
				int maxBlockedIPCacheSize,
				String relevantPaths,
				String nonRelevantPaths,
				String alwaysAllowedIPs,
				String alwaysForbiddenIPs,
				String statusUri,
				String statusAllowedIPs,
				String collectorIntegration,
				long alwaysForbiddenBlockedRequests,
				int currentActiveCounters,
				int currentBlockedCounters,
				long currentSlotKey,
				long lastCompletedSlotKey,
				long totalRequests,
				long previousTotalRequests,
				int previousActiveCounters,
				int previousBlockedCounters,
				int activeSlots,
				boolean isStatusHost,
				boolean isCurrentHost
		) {
			this(
					monitorName, description, pipelineOrder, monitorMode, simulationMode, serverWideBlocking,
					httpStatusCode, allowedRequestsPerSlot, slotLength, numberOfSlots,
					shareOfRetainedFormerRequests, ipv4SubnetMask, ipv6SubnetMask, maxIPCacheSize,
					maxBlockedIPCacheSize, relevantPaths, nonRelevantPaths, alwaysAllowedIPs,
					alwaysForbiddenIPs, statusUri, statusAllowedIPs, collectorIntegration,
					false, "_adv",
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, previousTotalRequests,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}

		/**
		 * Overloaded constructor without collectorIntegration for backwards compatibility.
		 */
		public ValveSummaryDto(
				String monitorName,
				String description,
				int pipelineOrder,
				String monitorMode,
				boolean simulationMode,
				boolean serverWideBlocking,
				int httpStatusCode,
				int allowedRequestsPerSlot,
				int slotLength,
				int numberOfSlots,
				float shareOfRetainedFormerRequests,
				int ipv4SubnetMask,
				int ipv6SubnetMask,
				int maxIPCacheSize,
				int maxBlockedIPCacheSize,
				String relevantPaths,
				String nonRelevantPaths,
				String alwaysAllowedIPs,
				String alwaysForbiddenIPs,
				String statusUri,
				String statusAllowedIPs,
				long alwaysForbiddenBlockedRequests,
				int currentActiveCounters,
				int currentBlockedCounters,
				long currentSlotKey,
				long lastCompletedSlotKey,
				long totalRequests,
				long previousTotalRequests,
				int previousActiveCounters,
				int previousBlockedCounters,
				int activeSlots,
				boolean isStatusHost,
				boolean isCurrentHost
		) {
			this(
					monitorName, description, pipelineOrder, monitorMode, simulationMode, serverWideBlocking,
					httpStatusCode, allowedRequestsPerSlot, slotLength, numberOfSlots,
					shareOfRetainedFormerRequests, ipv4SubnetMask, ipv6SubnetMask, maxIPCacheSize,
					maxBlockedIPCacheSize, relevantPaths, nonRelevantPaths, alwaysAllowedIPs,
					alwaysForbiddenIPs, statusUri, statusAllowedIPs, "auto",
					false, "_adv",
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, previousTotalRequests,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}

		/**
		 * Overloaded constructor for backwards compatibility with tests and concise mock instantiation.
		 */
		public ValveSummaryDto(
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
			this(
					monitorName,
					null,
					pipelineOrder,
					monitorMode != null ? monitorMode : "BLOCKING",
					simulationMode,
					serverWideBlocking,
					429,
					allowedRequestsPerSlot,
					slotLength,
					numberOfSlots,
					0.8f,
					32,
					64,
					10000,
					10000,
					null,
					null,
					null,
					null,
					null,
					null,
					"auto",
					false,
					"_adv",
					0L,
					currentActiveCounters,
					currentBlockedCounters,
					currentSlotKey,
					lastCompletedSlotKey,
					totalRequests,
					previousTotalRequests,
					previousActiveCounters,
					previousBlockedCounters,
					numberOfSlots,
					false,
					false
			);
		}

		public String visitorCookieNameOrDefault() {
			return visitorCookieName != null && !visitorCookieName.isBlank() ? visitorCookieName : "_adv";
		}

		/**
		 * Computes an in-memory hash of configuration parameters (excluding transient traffic counters)
		 * to detect configuration drift and prevent redundant database writes.
		 */
		public int configHashCode() {
			return java.util.Objects.hash(
					monitorName, description, pipelineOrder, monitorMode, simulationMode, serverWideBlocking,
					httpStatusCode, allowedRequestsPerSlot, slotLength, numberOfSlots,
					Float.floatToIntBits(shareOfRetainedFormerRequests), ipv4SubnetMask, ipv6SubnetMask,
					maxIPCacheSize, maxBlockedIPCacheSize, relevantPaths, nonRelevantPaths,
					alwaysAllowedIPs, alwaysForbiddenIPs, statusUri, statusAllowedIPs, collectorIntegration,
					visitorCookieEnabled, visitorCookieNameOrDefault()
			);
		}
	}
}
