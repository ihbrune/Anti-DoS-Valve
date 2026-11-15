package org.henbru.antidos.collector.web;

import org.henbru.antidos.collector.config.CollectorMode;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ValveScopeRegistry;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * Controller advice providing common model attributes across all dashboard and fragment endpoints.
 */
@ControllerAdvice
@ConditionalOnWebApplication
public class GlobalModelAdvice {

	private final MonitoredValveRepository monitoredValveRepository;
	private final CollectorProperties properties;

	public GlobalModelAdvice(@Autowired(required = false) MonitoredValveRepository monitoredValveRepository) {
		this(monitoredValveRepository, null);
	}

	@Autowired
	public GlobalModelAdvice(
			@Autowired(required = false) MonitoredValveRepository monitoredValveRepository,
			@Autowired(required = false) CollectorProperties properties) {
		this.monitoredValveRepository = monitoredValveRepository;
		this.properties = properties;
	}

	/**
	 * Makes the fleet ValveScopeRegistry accessible in all Thymeleaf templates and fragments under {@code valveScopes}.
	 */
	@ModelAttribute("valveScopes")
	public ValveScopeRegistry valveScopes() {
		return monitoredValveRepository != null
				? monitoredValveRepository.getValveScopeRegistry()
				: new ValveScopeRegistry(java.util.Map.of());
	}

	@ModelAttribute("viewerMode")
	public boolean viewerMode() {
		return properties != null && properties.isViewerMode();
	}

	@ModelAttribute("collectorMode")
	public String collectorMode() {
		return properties != null ? properties.getMode().name() : CollectorMode.FULL.name();
	}
}

