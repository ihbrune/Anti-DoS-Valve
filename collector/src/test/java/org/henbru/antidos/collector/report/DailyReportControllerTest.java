package org.henbru.antidos.collector.report;

import java.time.LocalDate;
import org.henbru.antidos.collector.model.DailyReport;
import org.henbru.antidos.collector.storage.DailyReportRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class DailyReportControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private DailyReportService dailyReportService;

	@Autowired
	private DailyReportRepository dailyReportRepository;

	private final LocalDate testDate = LocalDate.of(2026, 10, 25);

	@BeforeEach
	void setUp() {
		dailyReportRepository.deleteByReportDate(testDate.toString());
		dailyReportService.generateDailyReport(testDate);
	}

	@Test
	void testReportsPageLoads() throws Exception {
		mockMvc.perform(get("/reports"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
				.andExpect(content().string(containsString("Operational Day Reports &amp; Archive")))
				.andExpect(content().string(containsString(testDate.toString())))
				.andExpect(content().string(containsString("Copy Markdown")));
	}

	@Test
	void testReportByDateQuery() throws Exception {
		mockMvc.perform(get("/reports?date=" + testDate))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Report for " + testDate)))
				.andExpect(content().string(containsString("Executive Summary")));
	}

	@Test
	void testReportContentFragment() throws Exception {
		mockMvc.perform(get("/reports/" + testDate + "/content"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("report-display-container")))
				.andExpect(content().string(containsString(testDate.toString())))
				.andExpect(content().string(containsString("Download .md")));
	}

	@Test
	void testDownloadMarkdownFile() throws Exception {
		mockMvc.perform(get("/reports/" + testDate + "/download"))
				.andExpect(status().isOk())
				.andExpect(header().string("Content-Disposition", containsString("attachment; filename=\"antidos-report-" + testDate + ".md\"")))
				.andExpect(content().string(containsString("# 🛡️ Anti-DoS Fleet Operational Report — " + testDate)));
	}

	@Test
	void testGenerateReportPost() throws Exception {
		LocalDate targetDate = LocalDate.of(2026, 10, 24);
		mockMvc.perform(post("/reports/generate")
						.param("date", targetDate.toString()))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/reports?date=" + targetDate))
				.andExpect(flash().attributeExists("successMessage"));
	}
}
