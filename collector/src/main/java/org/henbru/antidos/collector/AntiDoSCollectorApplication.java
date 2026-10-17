package org.henbru.antidos.collector;

import org.henbru.antidos.collector.cli.CollectorCliRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main entry point for the Anti-DoS Collector and Analytics service.
 */
@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan
public class AntiDoSCollectorApplication {

	public static void main(String[] args) {
		if (CollectorCliRunner.isCliCommand(args)) {
			int exitCode = CollectorCliRunner.runCli(args);
			System.exit(exitCode);
			return;
		}
		SpringApplication.run(AntiDoSCollectorApplication.class, args);
	}
}
