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
		String error,
		Long serverGenerationMs,
		Long payloadBytes
) {
	public ValveOverviewDto(String serverTime, List<ValveSummaryDto> valves, String error) {
		this(serverTime, valves, error, null, null);
	}

	public ValveOverviewDto(String serverTime, List<ValveSummaryDto> valves, String error, Long serverGenerationMs) {
		this(serverTime, valves, error, serverGenerationMs, null);
	}

	public ValveOverviewDto withPayloadBytes(long bytes) {
		return new ValveOverviewDto(serverTime, valves, error, serverGenerationMs, bytes);
	}

	public long payloadBytesOrDefault() {
		return payloadBytes != null ? payloadBytes : 0L;
	}

	public int serverGenerationMsOrDefault() {
		return serverGenerationMs != null ? serverGenerationMs.intValue() : 0;
	}
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
			boolean authTrackingEnabled,
			String authTrackingMode,
			String authCookieName,
			String authLoginPaths,
			int authSessionTtlSeconds,
			int maxAuthCacheSize,
			int activeAuthSessions,
			String relevantAuthScope,
			Integer activeSampleThreshold,
			Boolean dynamicMitigationEnabled,
			String mitigationUri,
			String mitigationAllowedIPs,
			Integer dynamicBlocksActiveCount,
			Long dynamicBlocksBlockedRequests,
			Long dynamicRulesRevision,
			Integer dynamicRulesHashVersion,
			Integer mitigationMinPrefixV4,
			Integer mitigationMinPrefixV6,
			Integer mitigationMaxTtlSeconds,
			Integer mitigationMaxActiveBlocks,
			Boolean alwaysAllowPrivateIPs,
			long alwaysForbiddenBlockedRequests,
			int currentActiveCounters,
			int currentBlockedCounters,
			long currentSlotKey,
			long lastCompletedSlotKey,
			long totalRequests,
			long totalAuthenticatedRequests,
			long previousTotalRequests,
			long previousAuthenticatedRequests,
			int previousActiveCounters,
			int previousBlockedCounters,
			int activeSlots,
			boolean isStatusHost,
			boolean isCurrentHost
	) {
		/**
		 * Overloaded constructor without alwaysAllowPrivateIPs for backwards compatibility.
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
				boolean visitorCookieEnabled,
				String visitorCookieName,
				boolean authTrackingEnabled,
				String authTrackingMode,
				String authCookieName,
				String authLoginPaths,
				int authSessionTtlSeconds,
				int maxAuthCacheSize,
				int activeAuthSessions,
				String relevantAuthScope,
				Integer activeSampleThreshold,
				Boolean dynamicMitigationEnabled,
				String mitigationUri,
				String mitigationAllowedIPs,
				Integer dynamicBlocksActiveCount,
				Long dynamicBlocksBlockedRequests,
				Long dynamicRulesRevision,
				Integer dynamicRulesHashVersion,
				Integer mitigationMinPrefixV4,
				Integer mitigationMinPrefixV6,
				Integer mitigationMaxTtlSeconds,
				Integer mitigationMaxActiveBlocks,
				long alwaysForbiddenBlockedRequests,
				int currentActiveCounters,
				int currentBlockedCounters,
				long currentSlotKey,
				long lastCompletedSlotKey,
				long totalRequests,
				long totalAuthenticatedRequests,
				long previousTotalRequests,
				long previousAuthenticatedRequests,
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
					visitorCookieEnabled, visitorCookieName,
					authTrackingEnabled, authTrackingMode, authCookieName, authLoginPaths,
					authSessionTtlSeconds, maxAuthCacheSize, activeAuthSessions,
					relevantAuthScope, activeSampleThreshold,
					dynamicMitigationEnabled, mitigationUri, mitigationAllowedIPs,
					dynamicBlocksActiveCount, dynamicBlocksBlockedRequests, dynamicRulesRevision,
					dynamicRulesHashVersion,
					mitigationMinPrefixV4, mitigationMinPrefixV6, mitigationMaxTtlSeconds, mitigationMaxActiveBlocks,
					false,
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, totalAuthenticatedRequests,
					previousTotalRequests, previousAuthenticatedRequests,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}

		/**
		 * Overloaded constructor without dynamicRulesHashVersion for backwards compatibility.
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
				boolean visitorCookieEnabled,
				String visitorCookieName,
				boolean authTrackingEnabled,
				String authTrackingMode,
				String authCookieName,
				String authLoginPaths,
				int authSessionTtlSeconds,
				int maxAuthCacheSize,
				int activeAuthSessions,
				String relevantAuthScope,
				Integer activeSampleThreshold,
				Boolean dynamicMitigationEnabled,
				String mitigationUri,
				String mitigationAllowedIPs,
				Integer dynamicBlocksActiveCount,
				Long dynamicBlocksBlockedRequests,
				Long dynamicRulesRevision,
				Integer mitigationMinPrefixV4,
				Integer mitigationMinPrefixV6,
				Integer mitigationMaxTtlSeconds,
				Integer mitigationMaxActiveBlocks,
				long alwaysForbiddenBlockedRequests,
				int currentActiveCounters,
				int currentBlockedCounters,
				long currentSlotKey,
				long lastCompletedSlotKey,
				long totalRequests,
				long totalAuthenticatedRequests,
				long previousTotalRequests,
				long previousAuthenticatedRequests,
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
					visitorCookieEnabled, visitorCookieName,
					authTrackingEnabled, authTrackingMode, authCookieName, authLoginPaths,
					authSessionTtlSeconds, maxAuthCacheSize, activeAuthSessions,
					relevantAuthScope, activeSampleThreshold,
					dynamicMitigationEnabled, mitigationUri, mitigationAllowedIPs,
					dynamicBlocksActiveCount, dynamicBlocksBlockedRequests, dynamicRulesRevision,
					1,
					mitigationMinPrefixV4, mitigationMinPrefixV6, mitigationMaxTtlSeconds, mitigationMaxActiveBlocks,
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, totalAuthenticatedRequests,
					previousTotalRequests, previousAuthenticatedRequests,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}

		/**
		 * Overloaded constructor without mitigation guardrail fields for backwards compatibility.
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
				boolean visitorCookieEnabled,
				String visitorCookieName,
				boolean authTrackingEnabled,
				String authTrackingMode,
				String authCookieName,
				String authLoginPaths,
				int authSessionTtlSeconds,
				int maxAuthCacheSize,
				int activeAuthSessions,
				String relevantAuthScope,
				Integer activeSampleThreshold,
				Boolean dynamicMitigationEnabled,
				String mitigationUri,
				String mitigationAllowedIPs,
				Integer dynamicBlocksActiveCount,
				Long dynamicBlocksBlockedRequests,
				Long dynamicRulesRevision,
				long alwaysForbiddenBlockedRequests,
				int currentActiveCounters,
				int currentBlockedCounters,
				long currentSlotKey,
				long lastCompletedSlotKey,
				long totalRequests,
				long totalAuthenticatedRequests,
				long previousTotalRequests,
				long previousAuthenticatedRequests,
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
					visitorCookieEnabled, visitorCookieName,
					authTrackingEnabled, authTrackingMode, authCookieName, authLoginPaths,
					authSessionTtlSeconds, maxAuthCacheSize, activeAuthSessions,
					relevantAuthScope, activeSampleThreshold,
					dynamicMitigationEnabled, mitigationUri, mitigationAllowedIPs,
					dynamicBlocksActiveCount, dynamicBlocksBlockedRequests, dynamicRulesRevision,
					1, 16, 32, 86400, 5000,
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, totalAuthenticatedRequests,
					previousTotalRequests, previousAuthenticatedRequests,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}
		/**
		 * Overloaded constructor without dynamicMitigation fields for backwards compatibility.
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
				boolean visitorCookieEnabled,
				String visitorCookieName,
				boolean authTrackingEnabled,
				String authTrackingMode,
				String authCookieName,
				String authLoginPaths,
				int authSessionTtlSeconds,
				int maxAuthCacheSize,
				int activeAuthSessions,
				String relevantAuthScope,
				Integer activeSampleThreshold,
				long alwaysForbiddenBlockedRequests,
				int currentActiveCounters,
				int currentBlockedCounters,
				long currentSlotKey,
				long lastCompletedSlotKey,
				long totalRequests,
				long totalAuthenticatedRequests,
				long previousTotalRequests,
				long previousAuthenticatedRequests,
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
					visitorCookieEnabled, visitorCookieName,
					authTrackingEnabled, authTrackingMode, authCookieName, authLoginPaths,
					authSessionTtlSeconds, maxAuthCacheSize, activeAuthSessions,
					relevantAuthScope, activeSampleThreshold,
					false, null, null, 0, 0L, 0L,
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, totalAuthenticatedRequests,
					previousTotalRequests, previousAuthenticatedRequests,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}
		/**
		 * Overloaded constructor without activeSampleThreshold for backwards compatibility.
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
				boolean visitorCookieEnabled,
				String visitorCookieName,
				boolean authTrackingEnabled,
				String authTrackingMode,
				String authCookieName,
				String authLoginPaths,
				int authSessionTtlSeconds,
				int maxAuthCacheSize,
				int activeAuthSessions,
				String relevantAuthScope,
				long alwaysForbiddenBlockedRequests,
				int currentActiveCounters,
				int currentBlockedCounters,
				long currentSlotKey,
				long lastCompletedSlotKey,
				long totalRequests,
				long totalAuthenticatedRequests,
				long previousTotalRequests,
				long previousAuthenticatedRequests,
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
					visitorCookieEnabled, visitorCookieName,
					authTrackingEnabled, authTrackingMode, authCookieName, authLoginPaths,
					authSessionTtlSeconds, maxAuthCacheSize, activeAuthSessions,
					relevantAuthScope, 0,
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, totalAuthenticatedRequests,
					previousTotalRequests, previousAuthenticatedRequests,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}

		/**
		 * Overloaded constructor without relevantAuthScope for backwards compatibility.
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
				boolean visitorCookieEnabled,
				String visitorCookieName,
				boolean authTrackingEnabled,
				String authTrackingMode,
				String authCookieName,
				String authLoginPaths,
				int authSessionTtlSeconds,
				int maxAuthCacheSize,
				int activeAuthSessions,
				long alwaysForbiddenBlockedRequests,
				int currentActiveCounters,
				int currentBlockedCounters,
				long currentSlotKey,
				long lastCompletedSlotKey,
				long totalRequests,
				long totalAuthenticatedRequests,
				long previousTotalRequests,
				long previousAuthenticatedRequests,
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
					visitorCookieEnabled, visitorCookieName,
					authTrackingEnabled, authTrackingMode, authCookieName, authLoginPaths,
					authSessionTtlSeconds, maxAuthCacheSize, activeAuthSessions,
					"ALL",
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, totalAuthenticatedRequests,
					previousTotalRequests, previousAuthenticatedRequests,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}
		/**
		 * Overloaded constructor without authTracking fields for backwards compatibility.
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
			this(
					monitorName, description, pipelineOrder, monitorMode, simulationMode, serverWideBlocking,
					httpStatusCode, allowedRequestsPerSlot, slotLength, numberOfSlots,
					shareOfRetainedFormerRequests, ipv4SubnetMask, ipv6SubnetMask, maxIPCacheSize,
					maxBlockedIPCacheSize, relevantPaths, nonRelevantPaths, alwaysAllowedIPs,
					alwaysForbiddenIPs, statusUri, statusAllowedIPs, collectorIntegration,
					visitorCookieEnabled, visitorCookieName,
					false, "OFF", null, null, 900, 50000, 0,
					alwaysForbiddenBlockedRequests, currentActiveCounters, currentBlockedCounters,
					currentSlotKey, lastCompletedSlotKey, totalRequests, 0L, previousTotalRequests, 0L,
					previousActiveCounters, previousBlockedCounters, activeSlots, isStatusHost, isCurrentHost
			);
		}

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

		public String authTrackingModeOrDefault() {
			return authTrackingMode != null && !authTrackingMode.isBlank() ? authTrackingMode : "OFF";
		}

		public String relevantAuthScopeOrDefault() {
			return relevantAuthScope != null && !relevantAuthScope.isBlank() ? relevantAuthScope : "ALL";
		}

		public int activeSampleThresholdOrDefault() {
			return activeSampleThreshold != null ? Math.max(0, activeSampleThreshold) : 0;
		}

		public boolean dynamicMitigationEnabledOrDefault() {
			return Boolean.TRUE.equals(dynamicMitigationEnabled);
		}

		public int dynamicBlocksActiveCountOrDefault() {
			return dynamicBlocksActiveCount != null ? Math.max(0, dynamicBlocksActiveCount) : 0;
		}

		public long dynamicBlocksBlockedRequestsOrDefault() {
			return dynamicBlocksBlockedRequests != null ? Math.max(0L, dynamicBlocksBlockedRequests) : 0L;
		}

		public long dynamicRulesRevisionOrDefault() {
			return dynamicRulesRevision != null ? Math.max(0L, dynamicRulesRevision) : 0L;
		}

		public int dynamicRulesHashVersionOrDefault() {
			return dynamicRulesHashVersion != null && dynamicRulesHashVersion > 0 ? dynamicRulesHashVersion : 1;
		}

		public int mitigationMinPrefixV4OrDefault() {
			return mitigationMinPrefixV4 != null && mitigationMinPrefixV4 > 0 ? mitigationMinPrefixV4 : 16;
		}

		public int mitigationMinPrefixV6OrDefault() {
			return mitigationMinPrefixV6 != null && mitigationMinPrefixV6 > 0 ? mitigationMinPrefixV6 : 32;
		}

		public int mitigationMaxTtlSecondsOrDefault() {
			return mitigationMaxTtlSeconds != null && mitigationMaxTtlSeconds > 0 ? mitigationMaxTtlSeconds : 86400;
		}

		public int mitigationMaxActiveBlocksOrDefault() {
			return mitigationMaxActiveBlocks != null && mitigationMaxActiveBlocks > 0 ? mitigationMaxActiveBlocks : 5000;
		}

		public boolean alwaysAllowPrivateIPsOrDefault() {
			return Boolean.TRUE.equals(alwaysAllowPrivateIPs);
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
					alwaysAllowedIPs, alwaysAllowPrivateIPsOrDefault(), alwaysForbiddenIPs, statusUri, statusAllowedIPs, collectorIntegration,
					visitorCookieEnabled, visitorCookieNameOrDefault(),
					relevantAuthScopeOrDefault(),
					activeSampleThresholdOrDefault(),
					dynamicMitigationEnabledOrDefault(), mitigationUri,
					mitigationMinPrefixV4OrDefault(), mitigationMinPrefixV6OrDefault(),
					mitigationMaxTtlSecondsOrDefault(), mitigationMaxActiveBlocksOrDefault(),
					authTrackingEnabled, authTrackingModeOrDefault(), authCookieName, authLoginPaths,
					authSessionTtlSeconds, maxAuthCacheSize
			);
		}
	}
}
