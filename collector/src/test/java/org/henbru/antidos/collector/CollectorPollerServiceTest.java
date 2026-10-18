package org.henbru.antidos.collector;

import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.poller.CollectorPollerService;
import org.henbru.antidos.collector.poller.ValveStatusClient;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class CollectorPollerServiceTest {

	@Autowired
	private CollectorPollerService pollerService;

	@MockBean
	private ValveStatusClient statusClient;

	@Autowired
	private HeartbeatRepository heartbeatRepository;

	@Autowired
	private SlotSnapshotRepository slotSnapshotRepository;

	@Autowired
	private ClientEventRepository clientEventRepository;

	@Autowired
	private PollEventLogRepository pollEventLogRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@BeforeEach
	@SuppressWarnings("unused")
	void setUp() {
		jdbcTemplate.update("DELETE FROM blocked_client_events");
		jdbcTemplate.update("DELETE FROM slot_snapshots");
		jdbcTemplate.update("DELETE FROM poll_event_log");
		jdbcTemplate.update("DELETE FROM endpoint_heartbeats");
	}

	@Test
	void testPollEndpointNormalFlow() throws Exception {
		EndpointConfig endpoint = new EndpointConfig("POLL-TEST-NODE", "http://localhost:8080/antidos-status", "tok", false, true);

		ValveOverviewDto.ValveSummaryDto summary = new ValveOverviewDto.ValveSummaryDto(
				"POLL_VALVE", 1, "BLOCKING", false, false, 50, 60, 5, 5, 1, 500L, 499L, 2000L, 200L, 10, 1
		);
		ValveOverviewDto overview = new ValveOverviewDto("2026-10-17T10:00:00Z", List.of(summary), null);
		when(statusClient.fetchOverview(any())).thenReturn(overview);

		ValveDetailsDto.SelectedSlotDto slotDto = new ValveDetailsDto.SelectedSlotDto(
				"previous", 4, 499L, false, "2026-10-17T09:59:00Z", "2026-10-17T10:00:00Z", 200L, 10, 1
		);
		ValveDetailsDto.BlockedClientDto blockedClient = new ValveDetailsDto.BlockedClientDto(
				"192.0.2.1", 60, 5, true, "2026-10-17T09:59:30Z"
		);
		ValveDetailsDto details = new ValveDetailsDto(
				"2026-10-17T10:00:00Z", null, slotDto, 1, "all", List.of(blockedClient), null
		);
		when(statusClient.fetchSlotDetails(any(), eq("POLL_VALVE"), eq("previous"), eq("all"), eq("all"), eq("0"))).thenReturn(details);

		pollerService.pollEndpoint(endpoint);

		// Verify heartbeat
		Optional<EndpointHeartbeat> hb = heartbeatRepository.findByServerId("POLL-TEST-NODE");
		assertTrue(hb.isPresent());
		assertTrue(hb.get().online());
		assertEquals(1, hb.get().valvesCount());

		// Verify snapshot
		Optional<Long> latestKey = slotSnapshotRepository.findLatestSlotKey("POLL-TEST-NODE", "POLL_VALVE");
		assertTrue(latestKey.isPresent());
		assertEquals(499L, latestKey.get());

		// Verify blocked event
		var events = clientEventRepository.findRecentEvents("POLL-TEST-NODE", "192.0.2.1", 10);
		assertFalse(events.isEmpty());
		assertEquals("192.0.2.1", events.getFirst().clientKey());
		assertEquals(60, events.getFirst().requestCount());

		// Verify poll event log entry
		var pollLogs = pollEventLogRepository.findRecent(null, "ALL", "POLL-TEST-NODE", 10);
		assertFalse(pollLogs.isEmpty());
		assertEquals("SUCCESS", pollLogs.getFirst().status());
		assertEquals(200, pollLogs.getFirst().httpStatusCode());
		assertEquals(1, pollLogs.getFirst().valvesPolled());
		assertEquals(1, pollLogs.getFirst().slotsIngested());
	}

	@Test
	void testPollEndpointSkipsAlreadyCompletedSlot() throws Exception {
		EndpointConfig endpoint = new EndpointConfig("DEDUP-TEST-NODE", "http://localhost:8080/antidos-status", "tok", false, true);

		ValveOverviewDto.ValveSummaryDto summary = new ValveOverviewDto.ValveSummaryDto(
				"DEDUP_VALVE", 1, "BLOCKING", false, false, 50, 60, 5, 5, 0, 500L, 499L, 2000L, 200L, 10, 0
		);
		ValveOverviewDto overview = new ValveOverviewDto("2026-10-17T10:00:00Z", List.of(summary), null);
		when(statusClient.fetchOverview(any())).thenReturn(overview);

		ValveDetailsDto.SelectedSlotDto slotDto = new ValveDetailsDto.SelectedSlotDto(
				"previous", 4, 499L, false, "2026-10-17T09:59:00Z", "2026-10-17T10:00:00Z", 200L, 10, 0
		);
		ValveDetailsDto details = new ValveDetailsDto(
				"2026-10-17T10:00:00Z", null, slotDto, 0, "all", List.of(), null
		);
		when(statusClient.fetchSlotDetails(any(), eq("DEDUP_VALVE"), eq("previous"), eq("all"), eq("all"), eq("0"))).thenReturn(details);

		// First poll: ingests slot 499L
		pollerService.pollEndpoint(endpoint);
		verify(statusClient, times(1)).fetchSlotDetails(any(), eq("DEDUP_VALVE"), eq("previous"), eq("all"), eq("all"), eq("0"));

		// Second poll in same slot interval: lastCompletedSlotKey is still 499L
		pollerService.pollEndpoint(endpoint);

		// fetchSlotDetails must NOT have been called a second time
		verify(statusClient, times(1)).fetchSlotDetails(any(), eq("DEDUP_VALVE"), eq("previous"), eq("all"), eq("all"), eq("0"));
	}

	@Test
	void testPollEndpointFailureLogging() throws Exception {
		EndpointConfig endpoint = new EndpointConfig("FAIL-TEST-NODE", "http://localhost:8080/antidos-status", null, false, true);
		when(statusClient.fetchOverview(any())).thenThrow(new java.io.IOException("Connection refused"));

		pollerService.pollEndpoint(endpoint);

		var failLogs = pollEventLogRepository.findRecent(null, "ERROR", "FAIL-TEST-NODE", 10);
		assertFalse(failLogs.isEmpty());
		assertEquals("ERROR", failLogs.getFirst().status());
		assertTrue(failLogs.getFirst().errorMessage().contains("Connection refused"));
	}

	@Test
	void testPollEndpointWithValveFiltering() throws Exception {
		EndpointConfig endpoint = new EndpointConfig("FILTER-TEST-NODE", "http://localhost:8080/antidos-status", "tok", false, true, List.of("VALVE-WANTED"));

		ValveOverviewDto.ValveSummaryDto vWanted = new ValveOverviewDto.ValveSummaryDto(
				"VALVE-WANTED", 1, "BLOCKING", false, false, 50, 60, 5, 5, 0, 500L, 499L, 1000L, 100L, 5, 0
		);
		ValveOverviewDto.ValveSummaryDto vIgnored = new ValveOverviewDto.ValveSummaryDto(
				"VALVE-IGNORED", 2, "MONITORING", false, false, 50, 60, 5, 0, 0, 500L, 499L, 100L, 10L, 0, 0
		);
		ValveOverviewDto overview = new ValveOverviewDto("2026-10-17T10:00:00Z", List.of(vWanted, vIgnored), null);
		when(statusClient.fetchOverview(any())).thenReturn(overview);

		ValveDetailsDto.SelectedSlotDto slotDto = new ValveDetailsDto.SelectedSlotDto(
				"previous", 4, 499L, false, "2026-10-17T09:59:00Z", "2026-10-17T10:00:00Z", 100L, 5, 0
		);
		ValveDetailsDto details = new ValveDetailsDto("2026-10-17T10:00:00Z", null, slotDto, 0, "all", List.of(), null);
		when(statusClient.fetchSlotDetails(any(), eq("VALVE-WANTED"), eq("previous"), eq("all"), eq("all"), eq("0"))).thenReturn(details);

		pollerService.pollEndpoint(endpoint);

		// Verify only 1 valve was recorded in heartbeat
		Optional<EndpointHeartbeat> hb = heartbeatRepository.findByServerId("FILTER-TEST-NODE");
		assertTrue(hb.isPresent());
		assertEquals(1, hb.get().valvesCount());

		// Wanted valve polled
		verify(statusClient, times(1)).fetchSlotDetails(any(), eq("VALVE-WANTED"), eq("previous"), eq("all"), eq("all"), eq("0"));
		// Ignored valve was never polled
		verify(statusClient, never()).fetchSlotDetails(any(), eq("VALVE-IGNORED"), any(), any(), any(), any());
	}

	@Test
	void testPollFleetParallelExecution() throws Exception {
		EndpointConfig ep1 = new EndpointConfig("FLEET-NODE-1", "http://node1:8080/antidos-status", null, false, true);
		EndpointConfig ep2 = new EndpointConfig("FLEET-NODE-2", "http://node2:8080/antidos-status", null, false, true);

		ValveOverviewDto.ValveSummaryDto v1 = new ValveOverviewDto.ValveSummaryDto(
				"V1", 1, "BLOCKING", false, false, 50, 60, 5, 2, 0, 500L, 499L, 500L, 50L, 2, 0
		);
		ValveOverviewDto overview1 = new ValveOverviewDto("2026-10-18T10:00:00Z", List.of(v1), null);

		ValveOverviewDto.ValveSummaryDto v2 = new ValveOverviewDto.ValveSummaryDto(
				"V2", 1, "BLOCKING", false, false, 50, 60, 5, 3, 0, 500L, 499L, 800L, 80L, 3, 0
		);
		ValveOverviewDto overview2 = new ValveOverviewDto("2026-10-18T10:00:00Z", List.of(v2), null);

		when(statusClient.fetchOverview(argThat(ep -> ep != null && "FLEET-NODE-1".equals(ep.getName())))).thenReturn(overview1);
		when(statusClient.fetchOverview(argThat(ep -> ep != null && "FLEET-NODE-2".equals(ep.getName())))).thenReturn(overview2);

		ValveDetailsDto.SelectedSlotDto slotDto = new ValveDetailsDto.SelectedSlotDto(
				"previous", 4, 499L, false, "2026-10-18T09:59:00Z", "2026-10-18T10:00:00Z", 50L, 2, 0
		);
		ValveDetailsDto details = new ValveDetailsDto("2026-10-18T10:00:00Z", null, slotDto, 0, "all", List.of(), null);
		when(statusClient.fetchSlotDetails(any(), any(), eq("previous"), any(), any(), any())).thenReturn(details);

		org.henbru.antidos.collector.config.CollectorProperties testProps = new org.henbru.antidos.collector.config.CollectorProperties();
		testProps.setEndpoints(List.of(ep1, ep2));
		testProps.setParallelFleetPolling(true);

		CollectorPollerService customPoller = new CollectorPollerService(
				testProps,
				statusClient,
				heartbeatRepository,
				slotSnapshotRepository,
				clientEventRepository,
				pollEventLogRepository
		);

		customPoller.pollFleet();

		// Verify both endpoints were polled and recorded heartbeats
		Optional<EndpointHeartbeat> hb1 = heartbeatRepository.findByServerId("FLEET-NODE-1");
		Optional<EndpointHeartbeat> hb2 = heartbeatRepository.findByServerId("FLEET-NODE-2");

		assertTrue(hb1.isPresent());
		assertTrue(hb1.get().online());
		assertEquals("FLEET-NODE-1", hb1.get().serverId());

		assertTrue(hb2.isPresent());
		assertTrue(hb2.get().online());
		assertEquals("FLEET-NODE-2", hb2.get().serverId());

		customPoller.shutdown();
	}
}
