package org.henbru.antidos.collector.web;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.henbru.antidos.collector.annotation.NetworkAnnotationService;
import org.henbru.antidos.collector.model.AnnotationTargetType;
import org.henbru.antidos.collector.model.AnnotationVerdict;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class NotesControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private NetworkAnnotationService annotationService;

	@Autowired
	private org.henbru.antidos.collector.storage.NetworkAnnotationRepository repository;

	@BeforeEach
	void setUp() {
		for (NetworkAnnotation a : repository.findAll("updated_desc")) {
			repository.deleteById(a.id());
		}
		annotationService.refreshCache();
	}

	@Test
	void testGetNotesPage() throws Exception {
		annotationService.saveAnnotation(null, AnnotationTargetType.ASN, "AS24940", AnnotationVerdict.SUSPICIOUS, "Test Note");

		mockMvc.perform(get("/notes"))
				.andExpect(status().isOk())
				.andExpect(view().name("notes"))
				.andExpect(model().attributeExists("annotations", "verdictCounts", "totalCount"))
				.andExpect(content().string(containsString("AS24940")))
				.andExpect(content().string(containsString("Suspicious")));
	}

	@Test
	void testGetNotesFragmentWithFilter() throws Exception {
		annotationService.saveAnnotation(null, AnnotationTargetType.ASN, "AS24940", AnnotationVerdict.SUSPICIOUS, "Hetzner Scanners");
		annotationService.saveAnnotation(null, AnnotationTargetType.SUBNET, "198.51.100.0/24", AnnotationVerdict.LEGITIMATE, "Partner API");

		mockMvc.perform(get("/notes/fragment").param("q", "Hetzner"))
				.andExpect(status().isOk())
				.andExpect(view().name("fragments/notes-list :: notesList"))
				.andExpect(content().string(containsString("AS24940")))
				.andExpect(content().string(not(containsString("198.51.100.0/24"))));
	}

	@Test
	void testNewNoteModalPrefill() throws Exception {
		mockMvc.perform(get("/notes/modal/new")
						.param("targetType", "ASN")
						.param("targetKey", "AS12345"))
				.andExpect(status().isOk())
				.andExpect(view().name("fragments/note-modal :: noteModal"))
				.andExpect(model().attribute("mode", "CREATE"))
				.andExpect(model().attribute("targetKey", "AS12345"));
	}

	@Test
	void testViewTargetModalForExistingAndNonExisting() throws Exception {
		annotationService.saveAnnotation(null, AnnotationTargetType.ASN, "AS24940", AnnotationVerdict.SUSPICIOUS, "Hetzner Note");

		// Existing note -> VIEW mode
		mockMvc.perform(get("/notes/modal/view-target")
						.param("targetType", "ASN")
						.param("targetKey", "AS24940"))
				.andExpect(status().isOk())
				.andExpect(view().name("fragments/note-modal :: noteModal"))
				.andExpect(model().attribute("mode", "VIEW"))
				.andExpect(content().string(containsString("Hetzner Note")));

		// Non-existing note -> CREATE mode with prefilled key
		mockMvc.perform(get("/notes/modal/view-target")
						.param("targetType", "SUBNET")
						.param("targetKey", "203.0.113.0/24"))
				.andExpect(status().isOk())
				.andExpect(view().name("fragments/note-modal :: noteModal"))
				.andExpect(model().attribute("mode", "CREATE"))
				.andExpect(model().attribute("targetKey", "203.0.113.0/24"));
	}

	@Test
	void testCreateAndThenDeleteNote() throws Exception {
		mockMvc.perform(post("/notes")
						.param("targetType", "ASN")
						.param("targetKey", "AS99999")
						.param("verdict", "MALICIOUS")
						.param("noteMarkdown", "### Malicious Botnet C2"))
				.andExpect(status().isOk())
				.andExpect(header().string("HX-Trigger", "annotationChanged"))
				.andExpect(content().string(containsString("AS99999")));

		NetworkAnnotation created = annotationService.findForAsn(99999L).orElseThrow();

		mockMvc.perform(delete("/notes/" + created.id()))
				.andExpect(status().isOk())
				.andExpect(header().string("HX-Trigger", "annotationChanged"))
				.andExpect(content().string(not(containsString("AS99999"))));
	}
}
