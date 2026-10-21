package org.henbru.antidos.collector.web;

import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.enrichment.CrawlerSyncService;
import org.henbru.antidos.collector.model.CrawlerFeed;
import org.henbru.antidos.collector.storage.CrawlerFeedRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Controller providing the crawler feed dashboard and manual sync triggers.
 */
@Controller
public class CrawlerController {

	private final CrawlerFeedRepository crawlerFeedRepository;
	private final CrawlerSyncService crawlerSyncService;
	private final CollectorProperties properties;

	public CrawlerController(
			CrawlerFeedRepository crawlerFeedRepository,
			CrawlerSyncService crawlerSyncService,
			CollectorProperties properties) {
		this.crawlerFeedRepository = crawlerFeedRepository;
		this.crawlerSyncService = crawlerSyncService;
		this.properties = properties;
	}

	@GetMapping("/crawlers")
	public String crawlersPage(Model model) {
		ensureInitialFeedsLoaded();
		populateModel(model);
		return "crawlers";
	}

	@PostMapping("/crawlers/{feedKey}/sync")
	public String syncSingleFeed(@PathVariable(name = "feedKey") String feedKey, Model model) {
		crawlerSyncService.syncFeedByKey(feedKey);
		populateModel(model);
		return "fragments/crawlers-table :: crawlersTable";
	}

	@PostMapping("/crawlers/sync-all")
	public String syncAllFeeds(Model model) {
		crawlerSyncService.syncAll();
		populateModel(model);
		return "fragments/crawlers-table :: crawlersTable";
	}

	private void ensureInitialFeedsLoaded() {
		if (!properties.getEnrichment().isEnabled()) {
			return;
		}
		List<CrawlerFeed> existing = crawlerFeedRepository.findAll();
		java.util.Set<String> existingKeys = new java.util.HashSet<>();
		for (CrawlerFeed f : existing) {
			if (f != null && f.feedKey() != null) {
				existingKeys.add(f.feedKey());
			}
		}
		for (var cfg : properties.getEnrichment().getCrawlerFeedsList()) {
			if (!existingKeys.contains(cfg.getKey())) {
				String initialStatus = !cfg.isEnabled() ? "DISABLED"
						: (!cfg.hasValidCategory() ? "INVALID_CONFIG" : "PENDING");
				String initialError = !cfg.hasValidCategory()
						? "Unknown category '" + cfg.getCategory() + "'. Allowed: " + org.henbru.antidos.collector.config.CrawlerFeedConfig.VALID_CATEGORIES
						: (!cfg.isEnabled() ? "Feed is disabled in configuration" : null);

				crawlerFeedRepository.upsert(new CrawlerFeed(
						cfg.getKey(),
						cfg.getName(),
						cfg.getCategory(),
						cfg.getUrl(),
						null,
						initialStatus,
						0,
						initialError
				));
			}
		}
	}

	private void populateModel(Model model) {
		List<CrawlerFeed> feeds = crawlerFeedRepository.findAll();
		model.addAttribute("feeds", feeds);
		model.addAttribute("syncEnabled", properties.getEnrichment().isCrawlerSyncEnabled());
		model.addAttribute("syncCron", properties.getEnrichment().getCrawlerSyncCron());
	}
}
