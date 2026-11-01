package org.henbru.antidos.collector.advisor;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Consolidated advisor report aggregating findings, priority counts, and ready-to-copy
 * configuration directives for Tomcat server.xml.
 */
public record AdvisorReport(
		Instant generatedAt,
		int windowHours,
		List<AdvisorFinding> findings,
		int criticalCount,
		int warningCount,
		int infoCount,
		Set<String> recommendedAlwaysAllowedSubnets,
		String consolidatedAlwaysAllowedRegex,
		String consolidatedServerXmlSnippet
) {}
