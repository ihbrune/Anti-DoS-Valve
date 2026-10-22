package org.henbru.antidos.collector.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Definition of a single monitored AntiDoSValve endpoint.
 */
public class EndpointConfig {

	private String name;
	private String url;
	private String token;
	private boolean pollIntermediateSlots = false;
	private boolean enabled = true;
	private List<EndpointValveConfig> valves = new ArrayList<>();

	public EndpointConfig() {
	}

	public EndpointConfig(String name, String url, String token, boolean pollIntermediateSlots, boolean enabled) {
		this(name, url, token, pollIntermediateSlots, enabled, new ArrayList<>());
	}

	public EndpointConfig(String name, String url, String token, boolean pollIntermediateSlots, boolean enabled, List<?> valves) {
		this.name = name;
		this.url = url;
		this.token = token;
		this.pollIntermediateSlots = pollIntermediateSlots;
		this.enabled = enabled;
		this.valves = new ArrayList<>();
		if (valves != null) {
			for (Object obj : valves) {
				if (obj instanceof EndpointValveConfig evc) {
					this.valves.add(evc);
				} else if (obj instanceof String s) {
					this.valves.add(new EndpointValveConfig(s.trim()));
				}
			}
		}
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public boolean isPollIntermediateSlots() {
		return pollIntermediateSlots;
	}

	public void setPollIntermediateSlots(boolean pollIntermediateSlots) {
		this.pollIntermediateSlots = pollIntermediateSlots;
	}

	public boolean getEnabled() {
		return enabled;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public List<EndpointValveConfig> getValves() {
		return valves;
	}

	public void setValves(List<EndpointValveConfig> valves) {
		this.valves = valves != null ? new ArrayList<>(valves) : new ArrayList<>();
	}

	public List<String> getValveNames() {
		if (valves == null) {
			return new ArrayList<>();
		}
		return valves.stream()
				.map(EndpointValveConfig::getName)
				.filter(n -> n != null && !n.isBlank())
				.toList();
	}

	/**
	 * Determines whether a specific valve should be polled.
	 * If no valves are explicitly listed, all valves are included by default.
	 */
	public boolean isValveIncluded(String valveName) {
		if (valves == null || valves.isEmpty()) {
			return true;
		}
		if (valveName == null) {
			return false;
		}
		return valves.stream().anyMatch(v -> v != null && v.getName() != null && v.getName().trim().equalsIgnoreCase(valveName.trim()));
	}

	/**
	 * Looks up the endpoint-specific configuration override for a valve.
	 */
	public Optional<EndpointValveConfig> findValveConfig(String valveName) {
		if (valves == null || valveName == null) {
			return Optional.empty();
		}
		return valves.stream()
				.filter(v -> v != null && v.getName() != null && v.getName().trim().equalsIgnoreCase(valveName.trim()))
				.findFirst();
	}

	@Override
	public String toString() {
		return "EndpointConfig{" +
				"name='" + name + '\'' +
				", url='" + url + '\'' +
				", pollIntermediateSlots=" + pollIntermediateSlots +
				", enabled=" + enabled +
				", valves=" + valves +
				'}';
	}
}
