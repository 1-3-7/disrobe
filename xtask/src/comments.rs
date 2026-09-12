use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::fileio::read_text_bounded;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

const SOURCE_TREES: [&str; 4] = ["crates", "xtask", "benches", "fuzz"];

const SKIPPED_COMPONENTS: [&str; 3] = ["target", "node_modules", "corpus"];

const MIN_SOURCES: usize = 1000;

const EXCERPT_CHARS: usize = 96;

const CHAR_LITERAL_BUDGET: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lexer {
    Code,
    LineComment,
    BlockComment(usize),
    Text,
    RawText(usize),
}

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    source: String,
    line: usize,
    column: usize,
    token: &'static str,
    excerpt: String,
}

impl Finding {
    fn render(&self) -> String {
        format!(
            "{}:{}:{} opens a `{}` comment: {}",
            self.source, self.line, self.column, self.token, self.excerpt
        )
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let sources: Vec<PathBuf> = surface(root)?;
    if sources.len() < MIN_SOURCES {
        bail!(
            "the rust source surface under {} resolved to {} file(s), fewer than the {MIN_SOURCES} \
             this check requires; a walk that finds almost nothing passes whatever the sources say",
            root.display(),
            sources.len()
        );
    }

    let mut findings: Vec<String> = Vec::new();
    for path in &sources {
        let relative: String = path.strip_prefix(root).map_or_else(
            |_| path.to_string_lossy().into_owned(),
            |rest: &Path| rest.to_string_lossy().replace('\\', "/"),
        );
        let text: String = read_text_bounded(path, MAX_SOURCE_BYTES)
            .wrap_err_with(|| format!("reading rust source {relative}"))?;
        let reading: Reading = read(&relative, &text);
        if let Some(unclosed) = reading.terminal.unclosed() {
            bail!(
                "the lexer reached the end of {relative} still inside {unclosed}, so it lost track \
                 of what is code and what is data in that file. every comment after the point it \
                 desynchronised would go unreported, and a clean result here would mean nothing. \
                 this is a defect in the check, not in the file"
            );
        }
        for finding in reading.findings {
            findings.push(finding.render());
        }
    }

    if !findings.is_empty() {
        bail!(
            "{} rust source location(s) open a comment. this codebase carries none: naming and the \
             per-crate notes hold what a comment would say, and a doc comment counts the same as any \
             other. a comment token inside a string literal, a raw string, or fixture data is not \
             reported, so every location below is a real comment in real code:\n  {}",
            findings.len(),
            findings.join("\n  ")
        );
    }

    println!(
        "xtask regen: {} rust source file(s) open no comment, counting `//`, `///`, `//!` and `/*`, \
         and reading comment tokens inside string and raw-string literals as the data they are",
        sources.len()
    );
    Ok(())
}

fn surface(root: &Path) -> Result<Vec<PathBuf>> {
    let mut sources: Vec<PathBuf> = Vec::new();
    for tree in SOURCE_TREES {
        let dir: PathBuf = root.join(tree);
        if !dir.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&dir)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|dirent: &walkdir::DirEntry| !is_skipped(dirent.path()))
        {
            let dirent: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", dir.display()))?;
            let path: &Path = dirent.path();
            if path.is_file() && is_rust(path) {
                sources.push(path.to_path_buf());
            }
        }
    }
    sources.sort();
    sources.dedup();
    Ok(sources)
}

fn is_skipped(path: &Path) -> bool {
    path.components().any(|component: Component<'_>| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name: &str| SKIPPED_COMPONENTS.contains(&name))
    })
}

fn is_rust(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext: &OsStr| ext.eq_ignore_ascii_case("rs"))
}

fn read(source: &str, text: &str) -> Reading {
    let chars: Vec<char> = text.chars().collect();
    let lines: Vec<&str> = text.lines().collect();
    let mut findings: Vec<Finding> = Vec::new();
    let mut state: Lexer = Lexer::Code;
    let mut index: usize = 0;
    let mut line: usize = 1;
    let mut column: usize = 1;

    while index < chars.len() {
        let current: char = chars[index];
        let next: Option<char> = chars.get(index + 1).copied();
        let mut step: usize = 1;

        match state {
            Lexer::Code => {
                if current == '/' && next == Some('/') {
                    findings.push(finding(source, &lines, line, column, "//"));
                    state = Lexer::LineComment;
                    step = 2;
                } else if current == '/' && next == Some('*') {
                    findings.push(finding(source, &lines, line, column, "/*"));
                    state = Lexer::BlockComment(1);
                    step = 2;
                } else if current == '"' {
                    state = Lexer::Text;
                } else if let Some(prefix) = raw_text_prefix(&chars, index) {
                    state = Lexer::RawText(prefix.hashes);
                    step = prefix.width;
                } else if current == 'b' && next == Some('"') && !joins_identifier(&chars, index) {
                    state = Lexer::Text;
                    step = 2;
                } else if current == '\''
                    && let Some(end) = char_literal_end(&chars, index)
                {
                    step = end - index + 1;
                }
            }
            Lexer::LineComment => {
                if current == '\n' {
                    state = Lexer::Code;
                }
            }
            Lexer::BlockComment(depth) => {
                if current == '/' && next == Some('*') {
                    state = Lexer::BlockComment(depth + 1);
                    step = 2;
                } else if current == '*' && next == Some('/') {
                    state = if depth <= 1 {
                        Lexer::Code
                    } else {
                        Lexer::BlockComment(depth - 1)
                    };
                    step = 2;
                }
            }
            Lexer::Text => {
                if current == '\\' {
                    step = 2;
                } else if current == '"' {
                    state = Lexer::Code;
                }
            }
            Lexer::RawText(hashes) => {
                if current == '"' && closes_raw_text(&chars, index, hashes) {
                    state = Lexer::Code;
                    step = hashes + 1;
                }
            }
        }

        for offset in 0..step {
            match chars.get(index + offset) {
                Some('\n') => {
                    line += 1;
                    column = 1;
                }
                Some(_) => column += 1,
                None => {}
            }
        }
        index += step;
    }

    Reading {
        findings,
        terminal: state,
    }
}

#[derive(Debug)]
struct Reading {
    findings: Vec<Finding>,
    terminal: Lexer,
}

impl Lexer {
    const fn unclosed(self) -> Option<&'static str> {
        match self {
            Self::Text => Some("a string literal"),
            Self::RawText(_) => Some("a raw string literal"),
            Self::BlockComment(_) => Some("a block comment"),
            Self::Code | Self::LineComment => None,
        }
    }
}

#[derive(Debug)]
struct RawPrefix {
    hashes: usize,
    width: usize,
}

fn raw_text_prefix(chars: &[char], index: usize) -> Option<RawPrefix> {
    if joins_identifier(chars, index) {
        return None;
    }
    let mut cursor: usize = index;
    if chars.get(cursor) == Some(&'b') {
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'r') {
        return None;
    }
    cursor += 1;
    let hashes: usize = chars.get(cursor..).map_or(0, |rest: &[char]| {
        rest.iter().take_while(|ch: &&char| **ch == '#').count()
    });
    cursor += hashes;
    if chars.get(cursor) != Some(&'"') {
        return None;
    }
    Some(RawPrefix {
        hashes,
        width: cursor - index + 1,
    })
}

fn closes_raw_text(chars: &[char], index: usize, hashes: usize) -> bool {
    chars
        .get(index + 1..index + 1 + hashes)
        .is_some_and(|rest: &[char]| rest.iter().all(|ch: &char| *ch == '#'))
}

fn joins_identifier(chars: &[char], index: usize) -> bool {
    index
        .checked_sub(1)
        .and_then(|before: usize| chars.get(before))
        .is_some_and(|ch: &char| ch.is_alphanumeric() || *ch == '_')
}

fn char_literal_end(chars: &[char], index: usize) -> Option<usize> {
    let mut cursor: usize = index + 1;
    if chars.get(cursor) == Some(&'\\') {
        cursor += 2;
        while cursor < chars.len()
            && chars[cursor] != '\''
            && cursor.saturating_sub(index) < CHAR_LITERAL_BUDGET
        {
            cursor += 1;
        }
        return (chars.get(cursor) == Some(&'\'')).then_some(cursor);
    }
    if chars.get(cursor).is_some() && chars.get(cursor + 1) == Some(&'\'') {
        return Some(cursor + 1);
    }
    None
}

fn finding(
    source: &str,
    lines: &[&str],
    line: usize,
    column: usize,
    token: &'static str,
) -> Finding {
    let text: &str = lines.get(line - 1).copied().unwrap_or_default().trim();
    let taken: String = text.chars().take(EXCERPT_CHARS).collect();
    let excerpt: String = if text.chars().count() > EXCERPT_CHARS {
        format!("{taken}...")
    } else {
        taken
    };
    Finding {
        source: source.to_owned(),
        line,
        column,
        token,
        excerpt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "crates/p/src/lib.rs";

    fn scan(source: &str, text: &str) -> Vec<Finding> {
        read(source, text).findings
    }

    fn tokens(text: &str) -> Vec<(usize, usize, &'static str)> {
        scan(SRC, text)
            .into_iter()
            .map(|f: Finding| (f.line, f.column, f.token))
            .collect()
    }

    #[test]
    fn a_line_comment_is_reported_with_its_position() {
        assert_eq!(
            tokens("let x: u8 = 1;\n    // stray note\n"),
            vec![(2, 5, "//")]
        );
    }

    #[test]
    fn a_doc_comment_counts_the_same_as_any_other() {
        assert_eq!(
            tokens("/// documents the item\npub fn f() {}\n"),
            vec![(1, 1, "//")]
        );
        assert_eq!(tokens("//! module note\n"), vec![(1, 1, "//")]);
    }

    #[test]
    fn a_block_comment_is_reported_once_however_deeply_nested() {
        assert_eq!(
            tokens("/* outer /* inner */ still outer */\nlet x: u8 = 1;\n"),
            vec![(1, 1, "/*")]
        );
    }

    #[test]
    fn code_after_a_nested_block_comment_closes_is_scanned_again() {
        let text: &str = "/* /* */ */\n// after\n";
        assert_eq!(tokens(text), vec![(1, 1, "/*"), (2, 1, "//")]);
    }

    #[test]
    fn a_url_inside_a_string_is_not_a_comment() {
        assert!(scan(SRC, "let u: &str = \"https://example.invalid/a\";\n").is_empty());
    }

    #[test]
    fn a_glob_pattern_and_a_slash_enum_value_are_not_comments() {
        let text: &str =
            "const G: &str = \"**/*.bin\";\nconst S: &str = \"/*\";\nconst L: &str = \"//\";\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn emitted_decompiler_output_is_not_a_comment() {
        let text: &str = "let out: String = format!(\"/* {} */\", name);\n";
        assert!(scan(SRC, text).is_empty());
    }

    #[test]
    fn a_raw_string_holding_another_language_is_not_a_comment() {
        let text: &str =
            "const SAMPLE: &str = r#\"\nimport \"pe\"\n// leading comment\nrule Demo {}\n\"#;\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn a_hashed_raw_string_ends_only_on_its_own_hash_count() {
        let text: &str = "const A: &str = r##\"a \"# still inside // here\"##;\n// real\n";
        assert_eq!(tokens(text), vec![(2, 1, "//")]);
    }

    #[test]
    fn a_line_continued_string_carrying_go_source_is_not_a_comment() {
        let text: &str =
            "const GO: &str = \"package main\\n\\\n//go:noinline\\n\\\nfunc f() {}\\n\";\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn an_escaped_quote_does_not_end_the_string_early() {
        let text: &str = "let s: &str = \"he said \\\" // not a comment\";\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn a_byte_string_and_a_raw_byte_string_are_read_as_literals() {
        let text: &str = "const A: &[u8] = b\"// bytes\";\nconst B: &[u8] = br#\"/* bytes */\"#;\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn a_slash_char_literal_does_not_open_a_comment() {
        let text: &str = "let a: char = '/';\nlet b: char = '/';\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn an_escaped_quote_char_literal_does_not_desynchronise_the_lexer() {
        let text: &str = "let q: char = '\\'';\nlet s: &str = \"// inside\";\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn a_lifetime_is_not_read_as_a_char_literal() {
        let text: &str = "fn f<'a>(x: &'a str) -> &'a str { x }\nlet s: &str = \"// inside\";\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn division_and_a_trailing_star_slash_in_code_are_not_comments() {
        assert!(scan(SRC, "let r: u32 = a / b;\nlet p: u32 = a * b / c;\n").is_empty());
    }

    #[test]
    fn an_identifier_ending_in_r_before_a_string_is_not_a_raw_prefix() {
        let text: &str = "let ptr: &str = \"// inside\";\nvar\"unterminated is not code\";\n";
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
    }

    #[test]
    fn a_comment_after_a_string_on_the_same_line_is_still_reported() {
        let text: &str = "let u: &str = \"https://example.invalid\"; // trailing note\n";
        assert_eq!(tokens(text), vec![(1, 42, "//")]);
    }

    #[test]
    fn a_file_that_lexes_cleanly_ends_back_in_code_state() {
        let text: &str = "const A: &str = r#\"raw\"#;\nlet c: char = '/';\nfn f() {}\n";
        assert_eq!(read(SRC, text).terminal.unclosed(), None);
    }

    #[test]
    fn an_unterminated_literal_is_reported_as_a_desynchronised_lexer() {
        assert_eq!(
            read(SRC, "let s: &str = \"never closed\n// swallowed\n")
                .terminal
                .unclosed(),
            Some("a string literal")
        );
        assert_eq!(
            read(SRC, "const A: &str = r#\"never closed\n")
                .terminal
                .unclosed(),
            Some("a raw string literal")
        );
        assert_eq!(
            read(SRC, "/* never closed\n").terminal.unclosed(),
            Some("a block comment")
        );
    }

    #[test]
    fn the_finding_quotes_the_line_it_found() {
        let found: Vec<Finding> = scan(SRC, "fn f() {}\n  /// documents nothing\n");
        assert_eq!(found.len(), 1, "{found:?}");
        let rendered: String = found[0].render();
        assert!(
            rendered.starts_with("crates/p/src/lib.rs:2:3"),
            "{rendered}"
        );
        assert!(rendered.contains("documents nothing"), "{rendered}");
    }
}
