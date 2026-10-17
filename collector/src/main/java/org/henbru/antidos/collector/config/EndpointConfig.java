package org.henbru.antidos.collector.config;

import java.util.ArrayList;
import java.util.List;

/**
 * Definition of a single monitored AntiDoSValve endpoint.
 */
public class EndpointConfig {

	private String name;
	private String url;
	private String token;
	private boolean pollIntermediateSlots = false;
	private boolean enabled = true;
	private List<String> valves = new ArrayList<>();

	public EndpointConfig() {
	}

	public EndpointConfig(String name, String url, String token, boolean pollIntermediateSlots, boolean enabled) {
		this(name, url, token, pollIntermediateSlots, enabled, new ArrayList<>());
	}

	public EndpointConfig(String name, String url, String token, boolean pollIntermediateSlots, boolean enabled, List<String> valves) {
		this.name = name;
		this.url = url;
		this.token = token;
		this.pollIntermediateSlots = pollIntermediateSlots;
		this.enabled = enabled;
		this.valves = valves != null ? new ArrayList<>(valves) : new ArrayList<>();
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

	public List<String> getValves() {
		return valves;
	}

	public void setValves(List<String> valves) {
		this.valves = valves != null ? new ArrayList<>(valves) : new ArrayList<>();
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
		return valves.stream().anyMatch(v -> v != null && v.trim().equalsIgnoreCase(valveName.trim()));
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
