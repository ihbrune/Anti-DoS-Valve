package org.henbru.antidos.collector.diagnosis;

import java.time.Instant;
import java.util.List;

/**
 * Input parameters for performing a read-only Block Diagnosis (Support Lookup)
 * across dynamic mitigation rules, static valve configurations, and recorded events.
 */
public record BlockDiagnosisRequest(
		String ipAddress,
		String userAgent,
		String urlOrPath,
		Instant windowStart,
		Instant windowEnd,
		Instant referenceTime,
		List<String> serverIds,
		List<String> valveNames,
		boolean assumeAuthenticated,
		boolean assumeReturningVisitor
) {
}
