package org.henbru.antidos.collector.web;

import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.annotation.NetworkAnnotationService;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.AnnotationTargetType;
import org.henbru.antidos.collector.model.AnnotationVerdict;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Web controller serving the Network Notes &amp; Investigative Annotations dashboard (/notes)
 * and interactive HTMX modal endpoints for creating, editing, viewing, and deleting notes.
 */
@Controller
public class NotesController {

	private final NetworkAnnotationService annotationService;
	private final CollectorProperties properties;

	public NotesController(NetworkAnnotationService annotationService, CollectorProperties properties) {
		this.annotationService = annotationService;
		this.properties = properties;
	}

	@ModelAttribute("demoMode")
	public boolean demoMode() {
		return properties.isDemoMode();
	}

	@GetMapping("/notes")
	public String notesPage(
			@RequestParam(required = false) AnnotationTargetType targetType,
			@RequestParam(required = false) AnnotationVerdict verdict,
			@RequestParam(required = false, name = "q") String query,
			@RequestParam(required = false, defaultValue = "updated_desc") String sortBy,
			Model model
	) {
		populateNotesModel(model, targetType, verdict, query, sortBy);
		return "notes";
	}

	@GetMapping("/notes/fragment")
	public String notesListFragment(
			@RequestParam(required = false) AnnotationTargetType targetType,
			@RequestParam(required = false) AnnotationVerdict verdict,
			@RequestParam(required = false, name = "q") String query,
			@RequestParam(required = false, defaultValue = "updated_desc") String sortBy,
			Model model
	) {
		populateNotesModel(model, targetType, verdict, query, sortBy);
		return "fragments/notes-list :: notesList";
	}

	@GetMapping("/notes/modal/new")
	public String newNoteModal(
			@RequestParam(required = false) AnnotationTargetType targetType,
			@RequestParam(required = false) String targetKey,
			@RequestParam(required = false) AnnotationVerdict verdict,
			@RequestParam(required = false, defaultValue = "list") String context,
			Model model
	) {
		model.addAttribute("mode", "CREATE");
		model.addAttribute("targetType", targetType != null ? targetType : AnnotationTargetType.SUBNET);
		model.addAttribute("targetKey", targetKey != null ? targetKey.trim() : "");
		model.addAttribute("verdict", verdict != null ? verdict : AnnotationVerdict.INFO);
		model.addAttribute("noteMarkdown", "");
		model.addAttribute("id", null);
		model.addAttribute("context", context);
		model.addAttribute("targetTypes", AnnotationTargetType.values());
		model.addAttribute("verdicts", AnnotationVerdict.values());
		return "fragments/note-modal :: noteModal";
	}

	@GetMapping("/notes/modal/edit/{id}")
	public String editNoteModal(
			@PathVariable long id,
			@RequestParam(required = false, defaultValue = "list") String context,
			Model model
	) {
		Optional<NetworkAnnotation> opt = annotationService.getAnnotationById(id);
		if (opt.isEmpty()) {
			return "fragments/note-modal :: noteNotFound";
		}
		NetworkAnnotation a = opt.get();
		model.addAttribute("mode", "EDIT");
		model.addAttribute("id", a.id());
		model.addAttribute("targetType", a.targetType());
		model.addAttribute("targetKey", a.targetKey());
		model.addAttribute("verdict", a.verdict());
		model.addAttribute("noteMarkdown", a.noteMarkdown());
		model.addAttribute("context", context);
		model.addAttribute("targetTypes", AnnotationTargetType.values());
		model.addAttribute("verdicts", AnnotationVerdict.values());
		return "fragments/note-modal :: noteModal";
	}

	@GetMapping("/notes/modal/view/{id}")
	public String viewNoteModal(
			@PathVariable long id,
			@RequestParam(required = false, defaultValue = "list") String context,
			Model model
	) {
		Optional<NetworkAnnotation> opt = annotationService.getAnnotationById(id);
		if (opt.isEmpty()) {
			return "fragments/note-modal :: noteNotFound";
		}
		NetworkAnnotation a = opt.get();
		model.addAttribute("mode", "VIEW");
		model.addAttribute("annotation", a);
		model.addAttribute("renderedHtml", annotationService.renderMarkdown(a.noteMarkdown()));
		model.addAttribute("context", context);
		return "fragments/note-modal :: noteModal";
	}

	@GetMapping("/notes/modal/view-target")
	public String viewTargetNoteModal(
			@RequestParam AnnotationTargetType targetType,
			@RequestParam String targetKey,
			@RequestParam(required = false, defaultValue = "table") String context,
			Model model
	) {
		Optional<NetworkAnnotation> opt = annotationService.getAnnotationByTarget(targetType, targetKey);
		if (opt.isPresent()) {
			NetworkAnnotation a = opt.get();
			model.addAttribute("mode", "VIEW");
			model.addAttribute("annotation", a);
			model.addAttribute("renderedHtml", annotationService.renderMarkdown(a.noteMarkdown()));
			model.addAttribute("context", context);
			return "fragments/note-modal :: noteModal";
		}

		// If no note exists yet for this target, open pre-filled create modal!
		model.addAttribute("mode", "CREATE");
		model.addAttribute("targetType", targetType);
		model.addAttribute("targetKey", targetKey);
		model.addAttribute("verdict", AnnotationVerdict.INFO);
		model.addAttribute("noteMarkdown", "");
		model.addAttribute("id", null);
		model.addAttribute("context", context);
		model.addAttribute("targetTypes", AnnotationTargetType.values());
		model.addAttribute("verdicts", AnnotationVerdict.values());
		return "fragments/note-modal :: noteModal";
	}

	@PostMapping("/notes")
	public String saveNote(
			@RequestParam(required = false) Long id,
			@RequestParam AnnotationTargetType targetType,
			@RequestParam String targetKey,
			@RequestParam AnnotationVerdict verdict,
			@RequestParam String noteMarkdown,
			@RequestParam(required = false, defaultValue = "list") String context,
			HttpServletResponse response,
			Model model
	) {
		NetworkAnnotation saved = annotationService.saveAnnotation(id, targetType, targetKey, verdict, noteMarkdown);
		response.addHeader("HX-Trigger", "annotationChanged");

		if ("table".equalsIgnoreCase(context)) {
			// When submitted from inline table button, switch to VIEW mode in the modal
			model.addAttribute("mode", "VIEW");
			model.addAttribute("annotation", saved);
			model.addAttribute("renderedHtml", annotationService.renderMarkdown(saved.noteMarkdown()));
			model.addAttribute("actionMessage", "Note saved successfully.");
			model.addAttribute("context", "table");
			return "fragments/note-modal :: noteModal";
		}

		// When submitted from /notes page, refresh list fragment
		populateNotesModel(model, null, null, null, "updated_desc");
		return "fragments/notes-list :: notesList";
	}

	@DeleteMapping("/notes/{id}")
	public String deleteNote(
			@PathVariable long id,
			@RequestParam(required = false, defaultValue = "list") String context,
			HttpServletResponse response,
			Model model
	) {
		annotationService.deleteAnnotation(id);
		response.addHeader("HX-Trigger", "annotationChanged");

		if ("table".equalsIgnoreCase(context) || "modal".equalsIgnoreCase(context)) {
			return "fragments/note-modal :: noteModalSuccess";
		}

		populateNotesModel(model, null, null, null, "updated_desc");
		return "fragments/notes-list :: notesList";
	}

	private void populateNotesModel(
			Model model,
			AnnotationTargetType targetType,
			AnnotationVerdict verdict,
			String query,
			String sortBy
	) {
		List<NetworkAnnotation> annotations = annotationService.getAnnotationsFiltered(targetType, verdict, query, sortBy);

		Map<Long, String> renderedHtmlMap = new HashMap<>();
		for (NetworkAnnotation a : annotations) {
			renderedHtmlMap.put(a.id(), annotationService.renderMarkdown(a.noteMarkdown()));
		}

		model.addAttribute("annotations", annotations);
		model.addAttribute("renderedHtmlMap", renderedHtmlMap);
		model.addAttribute("totalCount", annotationService.getTotalCount());
		model.addAttribute("verdictCounts", annotationService.getVerdictCounts());
		model.addAttribute("selectedTargetType", targetType);
		model.addAttribute("selectedVerdict", verdict);
		model.addAttribute("searchQuery", query != null ? query : "");
		model.addAttribute("sortBy", sortBy != null ? sortBy : "updated_desc");
		model.addAttribute("targetTypes", AnnotationTargetType.values());
		model.addAttribute("verdicts", AnnotationVerdict.values());
	}
}
