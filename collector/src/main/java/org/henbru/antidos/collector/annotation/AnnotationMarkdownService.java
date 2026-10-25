package org.henbru.antidos.collector.annotation;

import java.util.Arrays;
import java.util.List;
import org.commonmark.Extension;
import org.commonmark.ext.autolink.AutolinkExtension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.node.Link;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.springframework.stereotype.Service;

/**
 * Service for securely parsing and rendering operator markdown annotations into HTML.
 */
@Service
public class AnnotationMarkdownService {

	private final Parser parser;
	private final HtmlRenderer renderer;

	public AnnotationMarkdownService() {
		List<Extension> extensions = Arrays.asList(
				TablesExtension.create(),
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
	 * Converts markdown text into rendered HTML.
	 */
	public String renderToHtml(String markdown) {
		if (markdown == null || markdown.isBlank()) {
			return "";
		}
		Node document = parser.parse(markdown.trim());
		return renderer.render(document);
	}
}
