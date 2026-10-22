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

import org.commonmark.Extension;
import org.commonmark.ext.autolink.AutolinkExtension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.ext.heading.anchor.HeadingAnchorExtension;
import org.commonmark.ext.heading.anchor.IdGenerator;
import org.commonmark.node.AbstractVisitor;
import org.commonmark.node.Heading;
import org.commonmark.node.Node;
import org.commonmark.node.Text;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

/**
 * Service that loads, parses, and caches the embedded Collector README.md documentation
 * as rich HTML with automatic table of contents extraction, GFM tables, and heading anchors.
 */
@Service
public class DocumentationService {

	private static final Logger log = LoggerFactory.getLogger(DocumentationService.class);

	private static final String CLASSPATH_README = "docs/README.md";

	public record DocumentationTocItem(int level, String title, String anchorId) {}

	public record DocumentationPayload(String html, List<DocumentationTocItem> tableOfContents) {}

	private volatile DocumentationPayload cachedPayload;

	/**
	 * Returns the rendered documentation payload (HTML and TOC).
	 * Thread-safe and cached after first computation.
	 */
	public DocumentationPayload getDocumentation() {
		DocumentationPayload payload = cachedPayload;
		if (payload == null) {
			synchronized (this) {
				payload = cachedPayload;
				if (payload == null) {
					payload = loadAndRender();
					cachedPayload = payload;
				}
			}
		}
		return payload;
	}

	private DocumentationPayload loadAndRender() {
		String markdown = readReadmeMarkdown();
		if (markdown == null || markdown.isBlank()) {
			return new DocumentationPayload("<p class=\"text-muted\">Documentation unavailable.</p>", Collections.emptyList());
		}

		List<Extension> extensions = Arrays.asList(
				TablesExtension.create(),
				HeadingAnchorExtension.create(),
				AutolinkExtension.create()
		);

		Parser parser = Parser.builder().extensions(extensions).build();
		HtmlRenderer renderer = HtmlRenderer.builder().extensions(extensions).build();

		Node document = parser.parse(markdown);

		// Extract Table of Contents for H2 and H3 headings
		List<DocumentationTocItem> toc = new ArrayList<>();
		IdGenerator idGenerator = IdGenerator.builder().build();

		document.accept(new AbstractVisitor() {
			@Override
			public void visit(Heading heading) {
				int level = heading.getLevel();
				if (level == 2 || level == 3) {
					StringBuilder textCollector = new StringBuilder();
					heading.accept(new AbstractVisitor() {
						@Override
						public void visit(Text text) {
							textCollector.append(text.getLiteral());
						}
					});
					String title = textCollector.toString().trim();
					if (!title.isEmpty()) {
						String anchorId = idGenerator.generateId(title);
						toc.add(new DocumentationTocItem(level, title, anchorId));
					}
				}
				visitChildren(heading);
			}
		});

		String html = renderer.render(document);
		log.info("Rendered embedded Collector documentation ({} chars, {} TOC items)", html.length(), toc.size());
		return new DocumentationPayload(html, Collections.unmodifiableList(toc));
	}

	private String readReadmeMarkdown() {
		// 1. Try classpath resource (packaged JAR)
		try {
			ClassPathResource resource = new ClassPathResource(CLASSPATH_README);
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
			log.warn("Failed reading classpath documentation resource {}: {}", CLASSPATH_README, e.getMessage());
		}

		// 2. Fallback for IDE / local runs before packaging
		List<Path> candidatePaths = List.of(
				Path.of("collector/README.md"),
				Path.of("README.md"),
				Path.of("../collector/README.md")
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
