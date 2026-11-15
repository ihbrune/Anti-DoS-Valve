package org.henbru.antidos.collector.web;

import org.henbru.antidos.collector.config.CollectorMode;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ValveScopeRegistry;
import org.henbru.antidos.collector.security.CollectorAuthContext;
import org.henbru.antidos.collector.security.CollectorSecurityService;
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
	private final CollectorSecurityService securityService;

	public GlobalModelAdvice(@Autowired(required = false) MonitoredValveRepository monitoredValveRepository) {
		this(monitoredValveRepository, null, null);
	}

	public GlobalModelAdvice(
			@Autowired(required = false) MonitoredValveRepository monitoredValveRepository,
			@Autowired(required = false) CollectorProperties properties) {
		this(monitoredValveRepository, properties, null);
	}

	@Autowired
	public GlobalModelAdvice(
			@Autowired(required = false) MonitoredValveRepository monitoredValveRepository,
			@Autowired(required = false) CollectorProperties properties,
			@Autowired(required = false) CollectorSecurityService securityService) {
		this.monitoredValveRepository = monitoredValveRepository;
		this.properties = properties;
		this.securityService = securityService;
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

	@ModelAttribute("operatorMode")
	public boolean operatorMode() {
		return properties != null && properties.isOperatorMode();
	}

	@ModelAttribute("systemAdminReadOnly")
	public boolean systemAdminReadOnly() {
		return properties != null && !properties.canPerformSystemAdmin();
	}

	@ModelAttribute("collectorMode")
	public String collectorMode() {
		return properties != null ? properties.getEffectiveMode().name() : CollectorMode.FULL.name();
	}

	@ModelAttribute("authEnabled")
	public boolean authEnabled() {
		return securityService != null && securityService.hasConfiguredTokens();
	}

	@ModelAttribute("authenticatedPrincipalName")
	public String authenticatedPrincipalName() {
		CollectorAuthContext.AuthPrincipal principal = CollectorAuthContext.get();
		return principal != null ? principal.name() : null;
	}

	@ModelAttribute("authenticatedRole")
	public String authenticatedRole() {
		CollectorAuthContext.AuthPrincipal principal = CollectorAuthContext.get();
		return (principal != null && principal.role() != null) ? principal.role().name() : null;
	}

	@ModelAttribute("aiAgentMode")
	public boolean aiAgentMode() {
		return CollectorAuthContext.isAiAgent();
	}
}

