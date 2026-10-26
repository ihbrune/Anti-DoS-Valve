package org.henbru.antidos.collector;

import java.time.Instant;
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
	private org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@BeforeEach
	void setUp() {
		jdbcTemplate.update("DELETE FROM client_events");
		jdbcTemplate.update("DELETE FROM slot_snapshots");
		jdbcTemplate.update("DELETE FROM poll_event_log");
		jdbcTemplate.update("DELETE FROM endpoint_heartbeats");
		jdbcTemplate.update("DELETE FROM monitored_valves");
		pollerService.clearConfigHashes();
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

	@Test
	void testPollEndpointWithActiveTrackingRule() throws Exception {
		org.henbru.antidos.collector.config.CollectorProperties testProps = new org.henbru.antidos.collector.config.CollectorProperties();
		testProps.getValveRules().put("SUBNET-VALVE", new org.henbru.antidos.collector.config.ValveRuleConfig(true, 1, "2000"));

		EndpointConfig ep = new EndpointConfig("SUBNET-NODE", "http://subnet-host:8080/antidos-status", null, false, true);
		testProps.setEndpoints(List.of(ep));

		ValveOverviewDto.ValveSummaryDto v = new ValveOverviewDto.ValveSummaryDto(
				"SUBNET-VALVE", 1, "BLOCKING", false, false, 50, 60, 5, 3, 0, 500L, 499L, 800L, 80L, 3, 0
		);
		ValveOverviewDto overview = new ValveOverviewDto("2026-10-18T10:00:00Z", List.of(v), null);
		when(statusClient.fetchOverview(any())).thenReturn(overview);

		ValveDetailsDto.SelectedSlotDto slotDto = new ValveDetailsDto.SelectedSlotDto(
				"previous", 4, 499L, false, "2026-10-18T09:59:00Z", "2026-10-18T10:00:00Z", 50L, 2, 0
		);
		ValveDetailsDto details = new ValveDetailsDto("2026-10-18T10:00:00Z", null, slotDto, 0, "all", List.of(), null);
		when(statusClient.fetchSlotDetails(any(), eq("SUBNET-VALVE"), eq("previous"), eq("all"), eq("all"), eq("2000"), isNull(), isNull(), eq(1)))
				.thenReturn(details);

		CollectorPollerService customPoller = new CollectorPollerService(
				testProps,
				statusClient,
				heartbeatRepository,
				slotSnapshotRepository,
				clientEventRepository,
				pollEventLogRepository
		);

		customPoller.pollFleet();

		verify(statusClient, times(1)).fetchSlotDetails(any(), eq("SUBNET-VALVE"), eq("previous"), eq("all"), eq("all"), eq("2000"), isNull(), isNull(), eq(1));
		customPoller.shutdown();
	}

	@Test
	void testPollerInMemoryConfigDirtyCheck() throws Exception {
		EndpointConfig endpoint = new EndpointConfig("DIRTY-CHECK-NODE", "http://localhost:8080/antidos-status", "tok", false, true);

		ValveOverviewDto.ValveSummaryDto v1 = new ValveOverviewDto.ValveSummaryDto(
				"RATE_LIMITER",
				"Description 1",
				1,
				"BLOCKING",
				false,
				false,
				429,
				50,
				60,
				5,
				0.8f,
				32,
				64,
				10000,
				10000,
				"/api/*",
				"*.css",
				"127.0.0.1",
				null,
				"/antidos-status",
				"127.0.0.1",
				0L,
				10,
				0,
				500L,
				499L,
				1000L,
				100L,
				10,
				0,
				5,
				true,
				true
		);
		when(statusClient.fetchOverview(any())).thenReturn(new ValveOverviewDto("2026-10-18T10:00:00Z", List.of(v1), null));

		ValveDetailsDto.SelectedSlotDto slotDto = new ValveDetailsDto.SelectedSlotDto(
				"previous", 4, 499L, false, "2026-10-18T09:59:00Z", "2026-10-18T10:00:00Z", 100L, 10, 0
		);
		when(statusClient.fetchSlotDetails(any(), any(), any(), any(), any(), any())).thenReturn(
				new ValveDetailsDto("2026-10-18T10:00:00Z", null, slotDto, 0, "all", List.of(), null)
		);

		// 1. First poll -> Must write to monitored_valves
		pollerService.pollEndpoint(endpoint);

		var valveOpt1 = monitoredValveRepository.findByServerIdAndValveName("DIRTY-CHECK-NODE", "RATE_LIMITER");
		assertTrue(valveOpt1.isPresent());
		assertEquals(50, valveOpt1.get().allowedRequestsPerSlot());
		assertEquals("Description 1", valveOpt1.get().description());
		Instant firstUpdated = valveOpt1.get().lastUpdatedAt();

		// Wait briefly to ensure timestamps would differ if written
		Thread.sleep(50);

		// 2. Second poll with SAME config (only transient traffic counter changed, e.g. totalRequests = 1200)
		ValveOverviewDto.ValveSummaryDto v1SameConfig = new ValveOverviewDto.ValveSummaryDto(
				"RATE_LIMITER",
				"Description 1",
				1,
				"BLOCKING",
				false,
				false,
				429,
				50,
				60,
				5,
				0.8f,
				32,
				64,
				10000,
				10000,
				"/api/*",
				"*.css",
				"127.0.0.1",
				null,
				"/antidos-status",
				"127.0.0.1",
				0L,
				15, // traffic counter changed
				0,
				500L,
				499L,
				1200L, // traffic counter changed
				100L,
				10,
				0,
				5,
				true,
				true
		);
		when(statusClient.fetchOverview(any())).thenReturn(new ValveOverviewDto("2026-10-18T10:00:15Z", List.of(v1SameConfig), null));

		pollerService.pollEndpoint(endpoint);

		var valveOpt2 = monitoredValveRepository.findByServerIdAndValveName("DIRTY-CHECK-NODE", "RATE_LIMITER");
		assertTrue(valveOpt2.isPresent());
		// In-Memory Dirty Check: Timestamp must be EXACTLY the same, meaning 0 DB writes occurred!
		assertEquals(firstUpdated, valveOpt2.get().lastUpdatedAt());

		// 3. Third poll with CHANGED config (allowedRequestsPerSlot = 80, description = "Updated Description")
		Thread.sleep(50);
		ValveOverviewDto.ValveSummaryDto v2ChangedConfig = new ValveOverviewDto.ValveSummaryDto(
				"RATE_LIMITER",
				"Updated Description",
				1,
				"BLOCKING",
				false,
				false,
				429,
				80, // changed!
				60,
				5,
				0.8f,
				32,
				64,
				10000,
				10000,
				"/api/*",
				"*.css",
				"127.0.0.1",
				null,
				"/antidos-status",
				"127.0.0.1",
				0L,
				15,
				0,
				500L,
				499L,
				1250L,
				100L,
				10,
				0,
				5,
				true,
				true
		);
		when(statusClient.fetchOverview(any())).thenReturn(new ValveOverviewDto("2026-10-18T10:00:30Z", List.of(v2ChangedConfig), null));

		pollerService.pollEndpoint(endpoint);

		var valveOpt3 = monitoredValveRepository.findByServerIdAndValveName("DIRTY-CHECK-NODE", "RATE_LIMITER");
		assertTrue(valveOpt3.isPresent());
		assertEquals(80, valveOpt3.get().allowedRequestsPerSlot());
		assertEquals("Updated Description", valveOpt3.get().description());
		assertNotEquals(firstUpdated, valveOpt3.get().lastUpdatedAt());
	}

	@Test
	void testPollEndpointVisitorCookieHandling() throws Exception {
		EndpointConfig endpoint = new EndpointConfig("COOKIE-TEST-NODE", "http://localhost:8080/antidos-status", "tok", false, true);

		ValveOverviewDto.ValveSummaryDto summary = new ValveOverviewDto.ValveSummaryDto(
				"COOKIE_VALVE", 1, "BLOCKING", false, false, 50, 60, 5, 5, 1, 500L, 499L, 2000L, 200L, 10, 1
		);
		ValveOverviewDto overview = new ValveOverviewDto("2026-10-17T10:00:00Z", List.of(summary), null);
		when(statusClient.fetchOverview(any())).thenReturn(overview);

		ValveDetailsDto.SelectedSlotDto slotDto = new ValveDetailsDto.SelectedSlotDto(
				"previous", 4, 499L, false, "2026-10-17T09:59:00Z", "2026-10-17T10:00:00Z", 200L, 10, 1
		);

		// Case 1: Header has visitorCookieEnabled = true
		ValveDetailsDto.ValveHeaderDto headerEnabled = new ValveDetailsDto.ValveHeaderDto(
				"COOKIE_VALVE", 500L, 499L, 60, 5, true
		);
		ValveDetailsDto.BlockedClientDto blockedClient = new ValveDetailsDto.BlockedClientDto(
				"192.0.2.1", 60, 5, 65, true, "2026-10-17T09:59:30Z", 1, 15, 3
		);
		ValveDetailsDto.ActiveClientDto activeClient = new ValveDetailsDto.ActiveClientDto(
				"192.0.2.2", 25, 0, 25, 50, 50, 1, 20, 1
		);
		ValveDetailsDto detailsEnabled = new ValveDetailsDto(
				"2026-10-17T10:00:00Z", headerEnabled, slotDto, 1, "all", null, null, List.of(blockedClient), 1, "all", null, null, null, List.of(activeClient), null
		);
		when(statusClient.fetchSlotDetails(any(), eq("COOKIE_VALVE"), eq("previous"), eq("all"), eq("all"), eq("0"))).thenReturn(detailsEnabled);

		pollerService.pollEndpoint(endpoint);

		var blockedEvents = clientEventRepository.findRecentEvents("COOKIE-TEST-NODE", "192.0.2.1", 5);
		assertFalse(blockedEvents.isEmpty());
		assertEquals(15, blockedEvents.getFirst().returningCount());
		assertEquals(3, blockedEvents.getFirst().authenticatedCount());

		var activeEvents = clientEventRepository.findRecentEvents("COOKIE-TEST-NODE", "192.0.2.2", 5);
		assertFalse(activeEvents.isEmpty());
		assertEquals(20, activeEvents.getFirst().returningCount());
		assertEquals(1, activeEvents.getFirst().authenticatedCount());

		// Case 2: Header has visitorCookieEnabled = false -> counts must be stored as null!
		ValveOverviewDto.ValveSummaryDto summary2 = new ValveOverviewDto.ValveSummaryDto(
				"COOKIE_VALVE", 1, "BLOCKING", false, false, 50, 60, 5, 5, 1, 501L, 500L, 2000L, 200L, 10, 1
		);
		when(statusClient.fetchOverview(any())).thenReturn(new ValveOverviewDto("2026-10-17T10:01:00Z", List.of(summary2), null));

		ValveDetailsDto.ValveHeaderDto headerDisabled = new ValveDetailsDto.ValveHeaderDto(
				"COOKIE_VALVE", 501L, 500L, 60, 5, false
		);
		ValveDetailsDto.SelectedSlotDto slotDto2 = new ValveDetailsDto.SelectedSlotDto(
				"previous", 4, 500L, false, "2026-10-17T10:00:00Z", "2026-10-17T10:01:00Z", 200L, 10, 1
		);
		ValveDetailsDto detailsDisabled = new ValveDetailsDto(
				"2026-10-17T10:01:00Z", headerDisabled, slotDto2, 1, "all", null, null, List.of(blockedClient), 1, "all", null, null, null, List.of(activeClient), null
		);
		when(statusClient.fetchSlotDetails(any(), eq("COOKIE_VALVE"), eq("previous"), eq("all"), eq("all"), eq("0"))).thenReturn(detailsDisabled);

		pollerService.pollEndpoint(endpoint);

		var blockedEventsDisabled = clientEventRepository.findRecentEvents("COOKIE-TEST-NODE", "192.0.2.1", 5)
				.stream().filter(e -> e.slotKey() == 500L).findFirst();
		assertTrue(blockedEventsDisabled.isPresent());
		assertNull(blockedEventsDisabled.get().returningCount(), "Should be null when visitor tracking is disabled");
	}
}

