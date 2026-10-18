package org.henbru.antidos.collector.enrichment;

import org.henbru.antidos.collector.model.IpEnrichmentResult;
import org.springframework.stereotype.Component;

/**
 * Fallback enrichment provider returning UNKNOWN metadata when enrichment is disabled or unconfigured.
 */
@Component
public class NoOpEnrichmentProvider implements IpEnrichmentService {

	@Override
	public IpEnrichmentResult enrich(String clientKey) {
		return IpEnrichmentResult.UNKNOWN;
	}
}
