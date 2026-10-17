package org.henbru.antidos.collector.cli;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.List;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.poller.ValveStatusClient;
import org.junit.jupiter.api.Test;

class CollectorCliRunnerTest {

	@Test
	void testIsCliCommand() {
		assertTrue(CollectorCliRunner.isCliCommand(new String[]{"test-endpoint", "--url", "http://localhost:8080"}));
		assertTrue(CollectorCliRunner.isCliCommand(new String[]{"add-endpoint", "--url", "http://localhost:8080"}));
		assertTrue(CollectorCliRunner.isCliCommand(new String[]{"--help"}));
		assertTrue(CollectorCliRunner.isCliCommand(new String[]{"-h"}));
		assertTrue(CollectorCliRunner.isCliCommand(new String[]{"help"}));

		assertFalse(CollectorCliRunner.isCliCommand(null));
		assertFalse(CollectorCliRunner.isCliCommand(new String[0]));
		assertFalse(CollectorCliRunner.isCliCommand(new String[]{"--server.port=9090"}));
	}

	@Test
	void testExecuteMissingUrl() {
		ValveStatusClient client = mock(ValveStatusClient.class);
		CollectorCliRunner runner = new CollectorCliRunner(client);

		int code = runner.execute("test-endpoint");
		assertEquals(1, code);
		verifyNoInteractions(client);
	}

	@Test
	void testExecuteHelp() {
		ValveStatusClient client = mock(ValveStatusClient.class);
		CollectorCliRunner runner = new CollectorCliRunner(client);

		int code = runner.execute("--help");
		assertEquals(0, code);
		verifyNoInteractions(client);
	}

	@Test
	void testExecuteSuccess() throws IOException, InterruptedException {
		ValveStatusClient client = mock(ValveStatusClient.class);
		ValveOverviewDto.ValveSummaryDto summary = new ValveOverviewDto.ValveSummaryDto(
				"TEST-VALVE", 1, "BLOCKING", false, false, 50, 60, 5, 10, 0, 100L, 99L, 500L, 400L, 5, 0);
		ValveOverviewDto dto = new ValveOverviewDto("2026-10-17T12:00:00Z", List.of(summary), null);
		when(client.fetchOverview(any())).thenReturn(dto);

		CollectorCliRunner runner = new CollectorCliRunner(client);
		int code = runner.execute("test-endpoint", "--url", "http://localhost:8080/antidos-status", "--token", "secret", "--name", "Node-A");
		assertEquals(0, code);
		verify(client, times(1)).fetchOverview(any());
	}
}
