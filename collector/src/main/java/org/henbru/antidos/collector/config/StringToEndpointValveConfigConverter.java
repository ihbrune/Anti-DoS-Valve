package org.henbru.antidos.collector.config;

import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

/**
 * Spring Converter that seamlessly converts scalar string entries in YAML
 * (e.g. {@code valves: ["Subnet-Guard", "Primary-Limiter"]}) to {@link EndpointValveConfig}
 * instances during Spring Boot configuration binding.
 */
@Component
@ConfigurationPropertiesBinding
public class StringToEndpointValveConfigConverter implements Converter<String, EndpointValveConfig> {

	@Override
	public EndpointValveConfig convert(@NonNull String source) {
		if (source.isBlank()) {
			return null;
		}
		return new EndpointValveConfig(source.trim());
	}
}
