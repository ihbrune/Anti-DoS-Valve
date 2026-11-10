package org.henbru.antidos.collector.web;

import org.henbru.antidos.collector.model.ValveScopeRegistry;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * Controller advice providing common model attributes across all dashboard and fragment endpoints.
 */
@ControllerAdvice
public class GlobalModelAdvice {

	private final MonitoredValveRepository monitoredValveRepository;

	@Autowired
	public GlobalModelAdvice(@Autowired(required = false) MonitoredValveRepository monitoredValveRepository) {
		this.monitoredValveRepository = monitoredValveRepository;
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
}

