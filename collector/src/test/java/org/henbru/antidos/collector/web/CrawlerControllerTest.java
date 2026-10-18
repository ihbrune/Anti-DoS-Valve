package org.henbru.antidos.collector.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@SuppressWarnings("null")
class CrawlerControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void testGetCrawlersPage() throws Exception {
		mockMvc.perform(get("/crawlers"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Verified Search Engine &amp; AI Crawler Feeds")))
				.andExpect(content().string(containsString("Googlebot")))
				.andExpect(content().string(containsString("OpenAI GPTBot")));
	}

	@Test
	void testSyncSingleFeedEndpoint() throws Exception {
		mockMvc.perform(post("/crawlers/googlebot/sync"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("id=\"crawlers-table-container\"")));
	}
}
