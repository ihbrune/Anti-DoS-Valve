package org.henbru.antidos.collector;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.poller.ValveStatusClient;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ValveStatusClientTest {

	private final ObjectMapper objectMapper = new ObjectMapper();

	@Test
	void testParseOverviewJson() throws Exception {
		String json = """
				{
				  "serverTime": "2026-10-17T10:30:00Z",
				  "valves": [
				    {
				      "monitorName": "STATUS VALVE",
				      "pipelineOrder": 1,
				      "monitorMode": "BLOCKING",
				      "simulationMode": false,
				      "serverWideBlocking": false,
				      "allowedRequestsPerSlot": 50,
				      "slotLength": 60,
				      "numberOfSlots": 5,
				      "currentActiveCounters": 10,
				      "currentBlockedCounters": 2,
				      "currentSlotKey": 174620,
				      "lastCompletedSlotKey": 174619,
				      "totalRequests": 5000,
				      "previousTotalRequests": 450,
				      "previousActiveCounters": 12,
				      "previousBlockedCounters": 2
				    }
				  ]
				}
				""";

		ValveOverviewDto dto = objectMapper.readValue(json, ValveOverviewDto.class);
		assertNotNull(dto);
		assertEquals("2026-10-17T10:30:00Z", dto.serverTime());
		assertNotNull(dto.valves());
		assertEquals(1, dto.valves().size());

		ValveOverviewDto.ValveSummaryDto v = dto.valves().getFirst();
		assertEquals("STATUS VALVE", v.monitorName());
		assertEquals(174620L, v.currentSlotKey());
		assertEquals(174619L, v.lastCompletedSlotKey());
		assertEquals(2, v.currentBlockedCounters());
		assertEquals(450L, v.previousTotalRequests());
	}

	@Test
	void testParseDetailsJson() throws Exception {
		String json = """
				{
				  "serverTime": "2026-10-17T10:30:00Z",
				  "valve": {
				    "monitorName": "STATUS VALVE",
				    "currentSlotKey": 174620,
				    "lastCompletedSlotKey": 174619,
				    "slotLength": 60,
				    "numberOfSlots": 5
				  },
				  "selectedSlot": {
				    "type": "previous",
				    "index": 4,
				    "slotKey": 174619,
				    "isCurrent": false,
				    "startTime": "2026-10-17T10:29:00Z",
				    "endTime": "2026-10-17T10:30:00Z",
				    "totalRequests": 1200,
				    "activeCounters": 40,
				    "blockedCounters": 2
				  },
				  "totalBlockedClients": 2,
				  "blockedLimit": "all",
				  "blockedClients": [
				    {
				      "key": "198.51.100.25",
				      "count": 75,
				      "retained": 10,
				      "locked": true,
				      "lastUpdate": "2026-10-17T10:29:45Z"
				    },
				    {
				      "key": "203.0.113.88",
				      "count": 60,
				      "retained": 0,
				      "locked": true,
				      "lastUpdate": "2026-10-17T10:29:50Z"
				    }
				  ]
				}
				""";

		ValveDetailsDto dto = objectMapper.readValue(json, ValveDetailsDto.class);
		assertNotNull(dto);
		assertNotNull(dto.selectedSlot());
		assertEquals("previous", dto.selectedSlot().type());
		assertEquals(174619L, dto.selectedSlot().slotKey());
		assertEquals(1200L, dto.selectedSlot().totalRequests());

		assertEquals(2, dto.totalBlockedClients());
		assertEquals("all", dto.blockedLimit());
		assertNotNull(dto.blockedClients());
		assertEquals(2, dto.blockedClients().size());
		assertEquals("198.51.100.25", dto.blockedClients().getFirst().key());
		assertEquals(75, dto.blockedClients().getFirst().count());
		assertTrue(dto.blockedClients().getFirst().locked());
	}

	@Test
	void testFormatErrorMessageConnectException() {
		java.net.ConnectException ce = new java.net.ConnectException(null);
		String msg = ValveStatusClient.formatErrorMessage(ce);
		assertTrue(msg.contains("Connection refused"), "Should indicate connection refused");
		assertTrue(msg.contains("port incorrect"), "Should mention port incorrect");

		java.io.IOException wrapped = new java.io.IOException(null, ce);
		String wrappedMsg = ValveStatusClient.formatErrorMessage(wrapped);
		assertTrue(wrappedMsg.contains("Connection refused"), "Wrapped ConnectException should be detected");
	}

	@Test
	void testFormatErrorMessageUnknownHost() {
		java.net.UnknownHostException uhe = new java.net.UnknownHostException("invalid-host.local");
		String msg = ValveStatusClient.formatErrorMessage(uhe);
		assertTrue(msg.contains("Host not found"), "Should indicate host not found");
		assertTrue(msg.contains("invalid-host.local"), "Should include host name");
	}

	@Test
	void testFormatErrorMessageNullMessageFallback() {
		Exception ex = new RuntimeException((String) null);
		String msg = ValveStatusClient.formatErrorMessage(ex);
		assertEquals("RuntimeException", msg, "Should fall back to simple class name instead of 'null'");
	}
}
