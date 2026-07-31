use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::fileio::read_text_bounded;

const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;

const ROOT_DOCUMENTS: [&str; 3] = ["README.md", "LEGAL.md", "SECURITY.md"];

const DOCUMENT_TREES: [&str; 5] = ["docs", "evidence", ".github", "editors", "plugins"];

const MIN_DOCUMENTS: usize = 100;

const MIN_FENCE_RUN: usize = 3;

const EXCERPT_CHARS: usize = 96;

const LONG_DASHES: [char; 4] = ['\u{2012}', '\u{2013}', '\u{2014}', '\u{2015}'];

const TYPED_DASH: &str = " -- ";

const EMOJI_RANGES: [(char, char); 11] = [
    ('\u{2049}', '\u{2049}'),
    ('\u{203c}', '\u{203c}'),
    ('\u{2139}', '\u{2139}'),
    ('\u{24c2}', '\u{24c2}'),
    ('\u{2600}', '\u{26ff}'),
    ('\u{2700}', '\u{27bf}'),
    ('\u{2b00}', '\u{2bff}'),
    ('\u{3030}', '\u{303d}'),
    ('\u{3297}', '\u{3299}'),
    ('\u{fe0f}', '\u{fe0f}'),
    ('\u{1f000}', '\u{1faff}'),
];

const LONG_DASH_RULE: &str = "a long dash";
const TYPED_DASH_RULE: &str = "a double hyphen standing in for a long dash";
const EMOJI_RULE: &str = "an emoji";

#[derive(Debug)]
struct Finding {
    document: String,
    line: usize,
    column: usize,
    rule: &'static str,
    excerpt: String,
}

impl Finding {
    fn render(&self) -> String {
        format!(
            "{}:{}:{} carries {}: {}",
            self.document, self.line, self.column, self.rule, self.excerpt
        )
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let documents: Vec<PathBuf> = surface(root)?;
    if documents.len() < MIN_DOCUMENTS {
        bail!(
            "the published markdown surface under {} resolved to {} document(s), fewer than the \
             {MIN_DOCUMENTS} this check requires; a walk that finds almost nothing passes whatever \
             the documents say",
            root.display(),
            documents.len()
        );
    }

    let mut findings: Vec<String> = Vec::new();
    for path in &documents {
        let relative: String = path.strip_prefix(root).map_or_else(
            |_| path.to_string_lossy().into_owned(),
            |rest: &Path| rest.to_string_lossy().replace('\\', "/"),
        );
        let text: String = read_text_bounded(path, MAX_DOCUMENT_BYTES)
            .wrap_err_with(|| format!("reading published document {relative}"))?;
        for finding in scan(&relative, &text) {
            findings.push(finding.render());
        }
    }

    if !findings.is_empty() {
        bail!(
            "{} published markdown location(s) carry a character this project does not put in front \
             of a reader. a long dash, a double hyphen used as one, and an emoji all read as \
             generated text rather than written text; rewrite the sentence with a comma, a colon, \
             or a full stop:\n  {}",
            findings.len(),
            findings.join("\n  ")
        );
    }

    println!(
        "xtask regen: {} published markdown document(s) carry no long dash, no double hyphen \
         standing in for one, and no emoji",
        documents.len()
    );
    Ok(())
}

fn surface(root: &Path) -> Result<Vec<PathBuf>> {
    let mut documents: Vec<PathBuf> = Vec::new();
    for name in ROOT_DOCUMENTS {
        let path: PathBuf = root.join(name);
        if !path.is_file() {
            bail!(
                "{name} is a published surface this check reads, but it is missing from {}, so the \
                 document a reader meets first would go unread",
                root.display()
            );
        }
        documents.push(path);
    }
    for tree in DOCUMENT_TREES {
        let dir: PathBuf = root.join(tree);
        if !dir.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&dir).sort_by_file_name() {
            let dirent: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", dir.display()))?;
            let path: &Path = dirent.path();
            if path.is_file() && is_markdown(path) {
                documents.push(path.to_path_buf());
            }
        }
    }
    documents.sort();
    documents.dedup();
    Ok(documents)
}

fn is_markdown(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext: &OsStr| ext.eq_ignore_ascii_case("md"))
}

fn scan(document: &str, text: &str) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    for (index, line) in text.lines().enumerate() {
        let number: usize = index + 1;
        let marker: Option<(char, usize)> = fence_marker(line);
        if let Some((open, width)) = fence {
            if let Some((closing, run)) = marker
                && closing == open
                && run >= width
            {
                fence = None;
            }
            continue;
        }
        if marker.is_some() {
            fence = marker;
            continue;
        }
        let scanned: String = without_code_spans(line);
        for (column, ch) in scanned.chars().enumerate() {
            let rule: &'static str = if LONG_DASHES.contains(&ch) {
                LONG_DASH_RULE
            } else if is_emoji(ch) {
                EMOJI_RULE
            } else {
                continue;
            };
            findings.push(Finding {
                document: document.to_owned(),
                line: number,
                column: column + 1,
                rule,
                excerpt: excerpt(line),
            });
        }
        if let Some(column) = typed_dash_column(&scanned) {
            findings.push(Finding {
                document: document.to_owned(),
                line: number,
                column,
                rule: TYPED_DASH_RULE,
                excerpt: excerpt(line),
            });
        }
    }
    findings
}

fn fence_marker(line: &str) -> Option<(char, usize)> {
    let trimmed: &str = line.trim_start();
    let marker: char = trimmed.chars().next()?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let run: usize = trimmed
        .chars()
        .take_while(|ch: &char| *ch == marker)
        .count();
    if run < MIN_FENCE_RUN {
        return None;
    }
    Some((marker, run))
}

fn without_code_spans(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out: String = String::with_capacity(line.len());
    let mut index: usize = 0;
    while index < chars.len() {
        let run: usize = backtick_run(&chars, index);
        if run == 0 {
            if let Some(ch) = chars.get(index) {
                out.push(*ch);
            }
            index += 1;
            continue;
        }
        let end: usize = closing_run(&chars, index + run, run)
            .map_or(index + run, |at: usize| at.saturating_add(run));
        for _ in index..end {
            out.push(' ');
        }
        index = end;
    }
    out
}

fn backtick_run(chars: &[char], from: usize) -> usize {
    chars.get(from..).map_or(0, |rest: &[char]| {
        rest.iter().take_while(|ch: &&char| **ch == '`').count()
    })
}

fn closing_run(chars: &[char], from: usize, width: usize) -> Option<usize> {
    let mut cursor: usize = from;
    while cursor < chars.len() {
        let run: usize = backtick_run(chars, cursor);
        if run == 0 {
            cursor += 1;
            continue;
        }
        if run == width {
            return Some(cursor);
        }
        cursor += run;
    }
    None
}

fn typed_dash_column(line: &str) -> Option<usize> {
    let at: usize = line.find(TYPED_DASH)?;
    let prefix: &str = line.get(..at)?;
    Some(prefix.chars().count() + 2)
}

fn is_emoji(ch: char) -> bool {
    EMOJI_RANGES
        .iter()
        .any(|(low, high): &(char, char)| (*low..=*high).contains(&ch))
}

fn excerpt(line: &str) -> String {
    let trimmed: &str = line.trim();
    let taken: String = trimmed.chars().take(EXCERPT_CHARS).collect();
    if trimmed.chars().count() > EXCERPT_CHARS {
        format!("{taken}...")
    } else {
        taken
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "README.md";

    #[test]
    fn an_em_dash_in_prose_is_reported() {
        let findings: Vec<Finding> = scan(DOC, "recovery is bounded \u{2014} by the artifact\n");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, LONG_DASH_RULE);
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].column, 21);
    }

    #[test]
    fn an_en_dash_is_reported_by_the_same_rule() {
        let findings: Vec<Finding> = scan(DOC, "CPython 3.0\u{2013}3.15\n");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, LONG_DASH_RULE);
    }

    #[test]
    fn an_emoji_in_prose_is_reported() {
        let findings: Vec<Finding> = scan(DOC, "every gate is green \u{2705}\n");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, EMOJI_RULE);
    }

    #[test]
    fn a_double_hyphen_standing_in_for_a_dash_is_reported() {
        let findings: Vec<Finding> = scan(DOC, "the gap -- the whole point -- is stated\n");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, TYPED_DASH_RULE);
        assert_eq!(findings[0].column, 9);
    }

    #[test]
    fn a_command_flag_inside_a_code_span_is_not_a_dash() {
        let findings: Vec<Finding> = scan(DOC, "run `cargo run -p xtask -- regen --check` first\n");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_fenced_block_may_carry_a_double_hyphen() {
        let text: &str =
            "prose\n```sh\ncargo test -p disrobe-cli -- --nocapture\n```\nmore prose\n";
        assert!(scan(DOC, text).is_empty());
    }

    #[test]
    fn a_dash_after_an_unterminated_code_span_is_still_reported() {
        let findings: Vec<Finding> = scan(DOC, "a stray ` backtick then \u{2014} a dash\n");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, LONG_DASH_RULE);
    }

    #[test]
    fn box_drawing_characters_are_not_emoji() {
        let text: &str = "   Raw  \u{2500}\u{2500}\u{25b2}  Disasm\n";
        assert!(scan("docs/src/ir-ladder.md", text).is_empty());
    }

    #[test]
    fn a_hyphenated_range_and_a_flag_in_prose_are_not_dashes() {
        let text: &str = "CPython 1.0-3.15 recovers, and --allow-dynamic gates the rest.\n";
        assert!(scan(DOC, text).is_empty());
    }

    #[test]
    fn a_copyright_sign_is_not_an_emoji() {
        assert!(scan("LEGAL.md", "\u{a9} 2026 Latency LLC, all rights reserved\n").is_empty());
    }

    #[test]
    fn a_finding_names_the_document_the_line_and_the_text() {
        let findings: Vec<Finding> = scan("docs/src/python.md", "one\ntwo \u{2014} three\n");
        assert_eq!(findings.len(), 1, "{findings:?}");
        let rendered: String = findings[0].render();
        assert!(rendered.starts_with("docs/src/python.md:2:5"), "{rendered}");
        assert!(rendered.contains("three"), "{rendered}");
    }

    #[test]
    fn a_long_excerpt_is_truncated_rather_than_printed_whole() {
        let line: String = "x".repeat(EXCERPT_CHARS + 10);
        let text: String = format!("{line}\u{2014}\n");
        let findings: Vec<Finding> = scan(DOC, &text);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].excerpt.ends_with("..."), "{findings:?}");
    }
}
