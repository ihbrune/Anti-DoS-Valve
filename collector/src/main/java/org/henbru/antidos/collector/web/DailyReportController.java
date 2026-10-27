package org.henbru.antidos.collector.web;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.DailyReport;
import org.henbru.antidos.collector.report.DailyReportService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Controller serving the Daily Operational Reports dashboard (/reports)
 * and endpoints for viewing, downloading, and on-demand generation.
 */
@Controller
public class DailyReportController {

	private static final Logger log = LoggerFactory.getLogger(DailyReportController.class);

	private final DailyReportService dailyReportService;
	private final CollectorProperties properties;

	public DailyReportController(DailyReportService dailyReportService, CollectorProperties properties) {
		this.dailyReportService = dailyReportService;
		this.properties = properties;
	}

	@ModelAttribute("demoMode")
	public boolean demoMode() {
		return properties.isDemoMode();
	}

	@GetMapping("/reports")
	public String reportsPage(
			@RequestParam(required = false) String date,
			Model model
	) {
		List<DailyReport> reports = dailyReportService.getRecentReports(90);
		model.addAttribute("reports", reports);

		DailyReport selected = null;
		if (date != null && !date.isBlank()) {
			Optional<DailyReport> found = dailyReportService.getReport(date.trim());
			if (found.isPresent()) {
				selected = found.get();
			}
		}

		if (selected == null && !reports.isEmpty()) {
			selected = reports.getFirst();
		}

		model.addAttribute("selectedReport", selected);
		model.addAttribute("selectedDate", selected != null ? selected.reportDate() : date);
		model.addAttribute("renderedHtml", selected != null ? dailyReportService.renderToHtml(selected.reportMarkdown()) : "");
		model.addAttribute("todayDate", LocalDate.now().toString());
		model.addAttribute("yesterdayDate", LocalDate.now().minusDays(1).toString());

		return "reports";
	}

	@GetMapping("/reports/{date}")
	public String reportByDate(@PathVariable String date) {
		return "redirect:/reports?date=" + date;
	}

	@GetMapping("/reports/{date}/content")
	public String reportContentFragment(@PathVariable String date, Model model) {
		Optional<DailyReport> found = dailyReportService.getReport(date.trim());
		DailyReport selected = found.orElse(null);
		model.addAttribute("selectedReport", selected);
		model.addAttribute("selectedDate", date);
		model.addAttribute("renderedHtml", selected != null ? dailyReportService.renderToHtml(selected.reportMarkdown()) : "");

		return "fragments/report-content :: reportContent";
	}

	@GetMapping("/reports/{date}/download")
	public ResponseEntity<byte[]> downloadMarkdown(@PathVariable String date) {
		Optional<DailyReport> found = dailyReportService.getReport(date.trim());
		if (found.isEmpty()) {
			return ResponseEntity.notFound().build();
		}

		DailyReport report = found.get();
		byte[] markdownBytes = report.reportMarkdown().getBytes(StandardCharsets.UTF_8);
		String filename = "antidos-report-" + report.reportDate() + ".md";

		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
				.contentType(new MediaType("text", "markdown", StandardCharsets.UTF_8))
				.contentLength(markdownBytes.length)
				.body(markdownBytes);
	}

	@PostMapping("/reports/generate")
	public String generateReport(
			@RequestParam(required = false) String date,
			RedirectAttributes redirectAttributes
	) {
		LocalDate targetDate;
		try {
			if (date != null && !date.isBlank()) {
				targetDate = LocalDate.parse(date.trim());
			} else {
				targetDate = LocalDate.now().minusDays(1);
			}
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("errorMessage", "Invalid date format: " + date + " (expected YYYY-MM-DD)");
			return "redirect:/reports";
		}

		try {
			DailyReport generated = dailyReportService.generateDailyReport(targetDate);
			redirectAttributes.addFlashAttribute("successMessage",
					"Report for " + targetDate + " generated successfully (" + generated.totalRequests() + " requests processed).");
			return "redirect:/reports?date=" + targetDate;
		} catch (Exception e) {
			log.error("Failed to generate daily report for {}: {}", targetDate, e.getMessage(), e);
			redirectAttributes.addFlashAttribute("errorMessage", "Error generating report for " + targetDate + ": " + e.getMessage());
			return "redirect:/reports";
		}
	}
}
