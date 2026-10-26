package org.henbru.antidos.collector.docs;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.commonmark.Extension;
import org.commonmark.ext.autolink.AutolinkExtension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.ext.heading.anchor.HeadingAnchorExtension;
import org.commonmark.ext.heading.anchor.IdGenerator;
import org.commonmark.node.AbstractVisitor;
import org.commonmark.node.Heading;
import org.commonmark.node.Link;
import org.commonmark.node.Node;
import org.commonmark.node.Text;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

/**
 * Service that loads, parses, and caches embedded Collector documentation guides:
 * - DASHBOARD_GUIDE.md: User interface, forensic views, and incident response manual
 * - SETUP_GUIDE.md: DevOps installation, systemd deployment, database config, and architecture
 * - README.md: High-level overview and landing documentation
 *
 * Supports on-demand extraction of individual sections by anchor ID for in-page contextual help drawers
 * and automatic rewriting of relative markdown links into in-app help routes (/help?doc=...).
 */
@Service
public class DocumentationService {

	private static final Logger log = LoggerFactory.getLogger(DocumentationService.class);

	public static final String DOC_UI = "ui";
	public static final String DOC_SETUP = "setup";
	public static final String DOC_README = "readme";

	public record DocumentationTocItem(int level, String title, String anchorId) {}

	public record DocumentationPayload(String docKey, String title, String html, List<DocumentationTocItem> tableOfContents) {}

	private final Map<String, DocumentationPayload> cachedPayloads = new ConcurrentHashMap<>();
	private final Map<String, Node> cachedAsts = new ConcurrentHashMap<>();
	private final Map<String, List<Heading>> cachedHeadings = new ConcurrentHashMap<>();

	private final List<Extension> extensions;
	private final Parser parser;
	private final HtmlRenderer renderer;

	public DocumentationService() {
		this.extensions = Arrays.asList(
				TablesExtension.create(),
				HeadingAnchorExtension.create(),
				AutolinkExtension.create()
		);
		this.parser = Parser.builder().extensions(extensions).build();

		HtmlRenderer.Builder rendererBuilder = HtmlRenderer.builder().extensions(extensions);
		rendererBuilder.attributeProviderFactory(context -> (node, tagName, attributes) -> {
			if (node instanceof Link && "a".equals(tagName)) {
				String href = attributes.get("href");
				if (href != null && (href.startsWith("http://") || href.startsWith("https://"))) {
					attributes.put("target", "_blank");
					attributes.put("rel", "noopener noreferrer");
				}
			}
		});
		this.renderer = rendererBuilder.build();
	}

	/**
	 * Returns the default documentation payload (UI Dashboard &amp; Forensics Guide).
	 */
	public DocumentationPayload getDocumentation() {
		return getDocumentation(DOC_UI);
	}

	/**
	 * Returns the rendered documentation payload for a specific document key ("ui", "setup", or "readme").
	 */
	public DocumentationPayload getDocumentation(String docKey) {
		String key = normalizeDocKey(docKey);
		return cachedPayloads.computeIfAbsent(key, this::loadAndRender);
	}

	/**
	 * Extracts and renders only the specific section matching sectionAnchor (including all child
	 * elements until the next heading of equal or higher level). Ideal for contextual help drawers.
	 */
	public String getSectionHtml(String docKey, String sectionAnchor) {
		String key = normalizeDocKey(docKey);
		ensureParsed(key);

		List<Heading> headings = cachedHeadings.get(key);
		if (headings == null || headings.isEmpty() || sectionAnchor == null || sectionAnchor.isBlank()) {
			return getDocumentation(key).html();
		}

		String cleanTarget = normalizeAnchor(sectionAnchor);
		IdGenerator idGen = IdGenerator.builder().build();

		Heading targetHeading = null;
		for (Heading h : headings) {
			String title = extractHeadingText(h);
			String anchorId = idGen.generateId(title);
			String simplifiedAnchor = anchorId.replace("-", "");
			String simplifiedTarget = cleanTarget.replace("-", "");

			if (anchorId.equalsIgnoreCase(cleanTarget)
					|| simplifiedAnchor.equalsIgnoreCase(simplifiedTarget)
					|| anchorId.startsWith(cleanTarget)
					|| cleanTarget.startsWith(anchorId)
					|| simplifiedAnchor.contains(simplifiedTarget)
					|| simplifiedTarget.contains(simplifiedAnchor)) {
				targetHeading = h;
				break;
			}
		}

		if (targetHeading == null) {
			log.debug("No section found matching anchor '{}' in doc '{}', returning full doc", sectionAnchor, key);
			return getDocumentation(key).html();
		}

		// Collect and render target heading and all subsequent siblings until next heading of <= level
		StringBuilder sb = new StringBuilder();
		int targetLevel = targetHeading.getLevel();
		Node current = targetHeading;

		while (current != null) {
			renderer.render(current, sb);
			current = current.getNext();
			if (current instanceof Heading nextHeading && nextHeading.getLevel() <= targetLevel) {
				break;
			}
		}

		return sb.toString();
	}

	private String normalizeDocKey(String docKey) {
		if (docKey == null) return DOC_UI;
		String lower = docKey.trim().toLowerCase();
		return switch (lower) {
			case "setup", "ops", "operations", "admin", "config" -> DOC_SETUP;
			case "readme", "overview", "landing" -> DOC_README;
			default -> DOC_UI;
		};
	}

	private String normalizeAnchor(String anchor) {
		String s = anchor.trim().toLowerCase();
		if (s.startsWith("#")) {
			s = s.substring(1);
		}
		return s;
	}

	private void ensureParsed(String key) {
		getDocumentation(key);
	}

	private DocumentationPayload loadAndRender(String key) {
		String markdown = readMarkdownContent(key);
		String docTitle = resolveDocTitle(key);

		if (markdown == null || markdown.isBlank()) {
			return new DocumentationPayload(key, docTitle,
					"<p class=\"text-muted\">Documentation unavailable for " + key + ".</p>",
					Collections.emptyList());
		}

		Node document = parser.parse(markdown);
		cachedAsts.put(key, document);

		List<DocumentationTocItem> toc = new ArrayList<>();
		List<Heading> headingNodes = new ArrayList<>();
		IdGenerator idGenerator = IdGenerator.builder().build();

		document.accept(new AbstractVisitor() {
			@Override
			public void visit(Heading heading) {
				headingNodes.add(heading);
				int level = heading.getLevel();
				if (level == 2 || level == 3) {
					String title = extractHeadingText(heading);
					if (!title.isEmpty()) {
						String anchorId = idGenerator.generateId(title);
						toc.add(new DocumentationTocItem(level, title, anchorId));
					}
				}
				visitChildren(heading);
			}
		});

		cachedHeadings.put(key, headingNodes);

		// Rewrite relative markdown cross-links into in-app help routes (/help?doc=...)
		document.accept(new AbstractVisitor() {
			@Override
			public void visit(Link link) {
				String dest = link.getDestination();
				if (dest != null && !dest.isBlank()) {
					String anchor = "";
					int hashIdx = dest.indexOf('#');
					if (hashIdx >= 0) {
						anchor = dest.substring(hashIdx);
						dest = dest.substring(0, hashIdx);
					}
					String cleanDest = dest.trim().toLowerCase();
					if (cleanDest.equals("dashboard_guide.md") || cleanDest.endsWith("/dashboard_guide.md")) {
						link.setDestination("/help?doc=ui" + anchor);
					} else if (cleanDest.equals("setup_guide.md") || cleanDest.endsWith("/setup_guide.md")) {
						link.setDestination("/help?doc=setup" + anchor);
					} else if (cleanDest.equals("readme.md") || cleanDest.endsWith("/readme.md")) {
						link.setDestination("/help?doc=readme" + anchor);
					}
				}
				visitChildren(link);
			}
		});

		String html = renderer.render(document);

		log.info("Rendered embedded Collector guide '{}' ({} chars, {} TOC items)", key, html.length(), toc.size());
		return new DocumentationPayload(key, docTitle, html, Collections.unmodifiableList(toc));
	}

	private String extractHeadingText(Heading heading) {
		StringBuilder textCollector = new StringBuilder();
		heading.accept(new AbstractVisitor() {
			@Override
			public void visit(Text text) {
				textCollector.append(text.getLiteral());
			}
		});
		return textCollector.toString().trim();
	}

	private String resolveDocTitle(String key) {
		return switch (key) {
			case DOC_SETUP -> "Setup, Deployment & Operations Guide";
			case DOC_README -> "Fleet Architecture & Management Guide";
			default -> "Dashboard & Forensics User Guide";
		};
	}

	private String readMarkdownContent(String key) {
		String filename = switch (key) {
			case DOC_SETUP -> "SETUP_GUIDE.md";
			case DOC_README -> "README.md";
			default -> "DASHBOARD_GUIDE.md";
		};

		// 1. Try classpath resource (packaged JAR)
		String classpathPath = "docs/" + filename;
		try {
			ClassPathResource resource = new ClassPathResource(classpathPath);
			if (resource.exists()) {
				try (InputStream is = resource.getInputStream();
					 BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
					StringBuilder sb = new StringBuilder();
					String line;
					while ((line = reader.readLine()) != null) {
						sb.append(line).append('\n');
					}
					return sb.toString();
				}
			}
		} catch (IOException e) {
			log.warn("Failed reading classpath documentation resource {}: {}", classpathPath, e.getMessage());
		}

		// 2. Fallback for IDE / local runs before packaging
		List<Path> candidatePaths = List.of(
				Path.of("collector/" + filename),
				Path.of(filename),
				Path.of("../collector/" + filename)
		);

		for (Path path : candidatePaths) {
			if (Files.isRegularFile(path)) {
				try {
					return Files.readString(path, StandardCharsets.UTF_8);
				} catch (IOException e) {
					log.warn("Failed reading markdown file at {}: {}", path, e.getMessage());
				}
			}
		}

		return null;
	}
}
