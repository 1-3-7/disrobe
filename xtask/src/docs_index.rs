use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::fileio::read_text_bounded;

const SITE: &str = "https://1-3-7.github.io/disrobe/";
const BOOK: &str = "https://1-3-7.github.io/disrobe/latest/";
const PAGES_MARKER: &str = "{{pages}}";
const MAX_DOC_BYTES: u64 = 2 * 1024 * 1024;
const PREFIX_SECTION: &str = "Introduction";

#[derive(Debug, PartialEq, Eq)]
struct Page {
    title: String,
    path: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Section {
    name: String,
    pages: Vec<Page>,
}

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let docs: PathBuf = root.join("docs");
    let summary: String = read_text_bounded(&docs.join("src").join("SUMMARY.md"), MAX_DOC_BYTES)?;
    let sections: Vec<Section> = parse_summary(&summary)?;
    let mut described: Vec<(String, Vec<(Page, String)>)> = Vec::with_capacity(sections.len());
    for section in sections {
        let mut pages: Vec<(Page, String)> = Vec::with_capacity(section.pages.len());
        for page in section.pages {
            let source: String =
                read_text_bounded(&docs.join("src").join(&page.path), MAX_DOC_BYTES)?;
            let Some(sentence) = first_sentence(&source) else {
                bail!(
                    "docs/src/{} has no prose paragraph to describe it in llms.txt",
                    page.path
                );
            };
            pages.push((page, sentence));
        }
        described.push((section.name, pages));
    }
    let template: String =
        read_text_bounded(&docs.join("theme").join("llms-template.md"), MAX_DOC_BYTES)?;
    let llms: String = render_llms(&template, &described)?;
    let sitemap: String = render_sitemap(&described);
    let outputs: [(PathBuf, String); 2] = [
        (docs.join("theme").join("llms.txt"), llms),
        (docs.join("theme").join("sitemap.xml"), sitemap),
    ];
    for (path, content) in &outputs {
        if check {
            let on_disk: String = read_text_bounded(path, MAX_DOC_BYTES)?;
            if on_disk != *content {
                bail!(
                    "{} is stale; run `cargo run -p xtask -- sync` to regenerate it from docs/src/SUMMARY.md",
                    path.display()
                );
            }
        } else {
            fs::write(path, content).wrap_err_with(|| format!("writing {}", path.display()))?;
        }
    }
    let count: usize = described
        .iter()
        .map(|(_, pages): &(String, Vec<(Page, String)>)| pages.len())
        .sum();
    println!("xtask docs-index: llms.txt and sitemap.xml cover {count} SUMMARY page(s)");
    Ok(())
}

fn parse_summary(summary: &str) -> Result<Vec<Section>> {
    let mut sections: Vec<Section> = Vec::new();
    for line in summary.lines() {
        let trimmed: &str = line.trim();
        if let Some(name) = trimmed.strip_prefix("# ") {
            if name != "Summary" {
                sections.push(Section {
                    name: name.to_owned(),
                    pages: Vec::new(),
                });
            }
            continue;
        }
        let Some(page) = summary_link(trimmed) else {
            continue;
        };
        if sections.is_empty() {
            sections.push(Section {
                name: PREFIX_SECTION.to_owned(),
                pages: Vec::new(),
            });
        }
        if let Some(section) = sections.last_mut() {
            section.pages.push(page);
        }
    }
    if sections
        .iter()
        .all(|section: &Section| section.pages.is_empty())
    {
        bail!("docs/src/SUMMARY.md lists no pages");
    }
    Ok(sections)
}

fn summary_link(line: &str) -> Option<Page> {
    let link: &str = line.strip_prefix("- ").unwrap_or(line);
    let rest: &str = link.strip_prefix('[')?;
    let (title, rest) = rest.split_once("](")?;
    let (target, tail) = rest.split_once(')')?;
    if !tail.trim().is_empty() || Path::new(target).extension() != Some(OsStr::new("md")) {
        return None;
    }
    let path: &str = target.strip_prefix("./").unwrap_or(target);
    Some(Page {
        title: title.to_owned(),
        path: path.to_owned(),
    })
}

fn first_sentence(markdown: &str) -> Option<String> {
    let mut in_fence: bool = false;
    let mut paragraph: String = String::new();
    for line in markdown.lines() {
        let trimmed: &str = line.trim();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if trimmed.is_empty() {
            if !paragraph.is_empty() {
                break;
            }
            continue;
        }
        let structural: bool = trimmed.starts_with('#')
            || trimmed.starts_with('<')
            || trimmed.starts_with('|')
            || trimmed.starts_with('>')
            || trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed.starts_with('!')
            || trimmed.starts_with("{{");
        if structural {
            if !paragraph.is_empty() {
                break;
            }
            continue;
        }
        if !paragraph.is_empty() {
            paragraph.push(' ');
        }
        paragraph.push_str(trimmed);
    }
    let plain: String = plain_text(&paragraph);
    let sentence: &str = sentence_prefix(&plain);
    let sentence: &str = sentence.trim();
    (!sentence.is_empty()).then(|| sentence.to_owned())
}

fn sentence_prefix(text: &str) -> &str {
    let bytes: &[u8] = text.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        let ends: bool = matches!(byte, b'.' | b'!' | b'?')
            && match (bytes.get(index + 1), bytes.get(index + 2)) {
                (None, _) => true,
                (Some(b' '), Some(next)) => next.is_ascii_uppercase(),
                _ => false,
            };
        if ends {
            return &text[..=index];
        }
    }
    text
}

fn plain_text(markdown: &str) -> String {
    let mut out: String = String::with_capacity(markdown.len());
    let mut rest: &str = markdown;
    while let Some(start) = rest.find('[') {
        out.push_str(&rest[..start]);
        let after: &str = &rest[start + 1..];
        match after
            .split_once("](")
            .and_then(|(text, tail)| tail.split_once(')').map(|(_, tail)| (text, tail)))
        {
            Some((text, tail)) if !text.contains(']') => {
                out.push_str(text);
                rest = tail;
            }
            _ => {
                out.push('[');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out.replace("**", "").replace('`', "")
}

fn page_url(path: &str) -> String {
    format!(
        "{BOOK}{}",
        path.trim_end_matches(".md").to_owned() + ".html"
    )
}

fn render_llms(template: &str, sections: &[(String, Vec<(Page, String)>)]) -> Result<String> {
    let Some((head, tail)) = template.split_once(PAGES_MARKER) else {
        bail!("docs/theme/llms-template.md has no {PAGES_MARKER} marker");
    };
    let mut pages: String = String::new();
    for (name, entries) in sections {
        let _ = writeln!(pages, "## {name}\n");
        for (page, sentence) in entries {
            let _ = writeln!(
                pages,
                "- [{}]({}): {sentence}",
                page.title,
                page_url(&page.path)
            );
        }
        pages.push('\n');
    }
    Ok(format!("{head}{}{tail}", pages.trim_end_matches('\n')))
}

fn render_sitemap(sections: &[(String, Vec<(Page, String)>)]) -> String {
    let mut out: String = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    let mut locations: Vec<String> = vec![SITE.to_owned(), format!("{BOOK}index.html")];
    locations.extend(
        sections
            .iter()
            .flat_map(|(_, entries): &(String, Vec<(Page, String)>)| entries.iter())
            .map(|(page, _): &(Page, String)| page_url(&page.path)),
    );
    locations.push(format!("{SITE}playground/"));
    for location in locations {
        let _ = writeln!(out, "  <url><loc>{location}</loc></url>");
    }
    out.push_str("</urlset>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_sections_keep_their_pages_and_prefix_chapters() -> Result<()> {
        let sections: Vec<Section> = parse_summary(
            "# Summary\n\n[Introduction](./introduction.md)\n\n# Guides\n\n- [Python](./languages/python.md)\n  - [Nested](./nested.md)\n---\n",
        )?;
        assert_eq!(
            sections,
            vec![
                Section {
                    name: PREFIX_SECTION.to_owned(),
                    pages: vec![Page {
                        title: "Introduction".to_owned(),
                        path: "introduction.md".to_owned()
                    }]
                },
                Section {
                    name: "Guides".to_owned(),
                    pages: vec![
                        Page {
                            title: "Python".to_owned(),
                            path: "languages/python.md".to_owned()
                        },
                        Page {
                            title: "Nested".to_owned(),
                            path: "nested.md".to_owned()
                        }
                    ]
                }
            ]
        );
        Ok(())
    }

    #[test]
    fn the_first_prose_sentence_skips_structure_and_strips_markup() {
        let page: &str = "# Title\n\n<div>x</div>\n\n```sh\ncode. here\n```\n\nThe [`auto`](./cli.md) command **chains** passes. Then more.\n";
        assert_eq!(
            first_sentence(page).as_deref(),
            Some("The auto command chains passes.")
        );
        assert_eq!(
            first_sentence("Version 1.1 applies to e.g. this file. Next one").as_deref(),
            Some("Version 1.1 applies to e.g. this file.")
        );
        assert_eq!(first_sentence("# Only a heading\n"), None);
    }

    #[test]
    fn llms_rendering_requires_the_pages_marker() {
        let result: Result<String> = render_llms(
            "# disrobe
",
            &[],
        );
        assert!(
            matches!(&result, Err(error) if error.to_string().contains("{{pages}}")),
            "{result:?}"
        );
    }
}
