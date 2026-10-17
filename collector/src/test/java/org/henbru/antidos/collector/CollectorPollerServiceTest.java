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
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

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
		when(statusClient.fetchSlotDetails(any(), eq("POLL_VALVE"), eq("previous"), eq("all"))).thenReturn(details);

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
		when(statusClient.fetchSlotDetails(any(), eq("VALVE-WANTED"), eq("previous"), eq("all"))).thenReturn(details);

		pollerService.pollEndpoint(endpoint);

		// Verify only 1 valve was recorded in heartbeat
		Optional<EndpointHeartbeat> hb = heartbeatRepository.findByServerId("FILTER-TEST-NODE");
		assertTrue(hb.isPresent());
		assertEquals(1, hb.get().valvesCount());

		// Wanted valve polled
		verify(statusClient, times(1)).fetchSlotDetails(any(), eq("VALVE-WANTED"), eq("previous"), eq("all"));
		// Ignored valve was never polled
		verify(statusClient, never()).fetchSlotDetails(any(), eq("VALVE-IGNORED"), any(), any());
	}
}
