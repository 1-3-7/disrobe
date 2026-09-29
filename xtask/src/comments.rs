use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use eyre::{Result, WrapErr, bail, eyre};

const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;

const SOURCE_TREES: [&str; 4] = ["crates", "xtask", "benches", "fuzz"];

const SKIPPED_COMPONENTS: [&str; 3] = ["target", "node_modules", "corpus"];

const MIN_SOURCES: usize = 1000;

const EXCERPT_CHARS: usize = 96;

const CHAR_LITERAL_BUDGET: usize = 12;

pub(crate) const PINNED_COMMENT_LINES: usize = 0;

const BANNED_WORDS: [&str; 5] = ["TODO", "FIXME", "XXX", "HACK", "NOTE"];

const CODE_OPENERS: [&str; 12] = [
    "let ", "fn ", "use ", "pub ", "impl ", "mod ", "struct ", "enum ", "const ", "static ",
    "return", "#[",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lexer {
    Code,
    LineComment,
    BlockComment(usize),
    Text,
    RawText(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentKind {
    Line,
    Block,
}

#[derive(Debug, PartialEq, Eq)]
struct Comment {
    source: String,
    line: usize,
    column: usize,
    kind: CommentKind,
    own_line: bool,
    after_token: String,
    excerpt: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Allowed,
    Rejected(&'static str),
}

impl Comment {
    fn verdict(&self) -> Verdict {
        if self.kind == CommentKind::Block {
            return Verdict::Rejected("a block or block doc comment");
        }
        if self.after_token.starts_with("//") {
            return Verdict::Rejected("a `////` comment");
        }
        if self.after_token.starts_with('/') {
            return Verdict::Rejected("a `///` doc comment");
        }
        if self.after_token.starts_with('!') {
            return Verdict::Rejected("a `//!` doc comment");
        }
        if !self.own_line {
            return Verdict::Rejected("a trailing comment");
        }
        let content: &str = self.after_token.trim();
        if content
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .any(|word: &str| BANNED_WORDS.contains(&word))
        {
            return Verdict::Rejected("a TODO-class marker");
        }
        if content.ends_with([';', '{', '}'])
            || CODE_OPENERS
                .iter()
                .any(|opener: &&str| content.starts_with(opener))
        {
            return Verdict::Rejected("code-shaped text");
        }
        Verdict::Allowed
    }

    fn render(&self, reason: &str) -> String {
        format!(
            "{}:{}:{} is {reason}: {}",
            self.source, self.line, self.column, self.excerpt
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Tally {
    rejected: Vec<String>,
    allowed_lines: usize,
}

pub(crate) fn run(root: &Path) -> Result<()> {
    run_at(root, "HEAD")
}

pub(crate) fn run_at(root: &Path, rev: &str) -> Result<()> {
    let sources: Vec<(String, String)> = committed_sources(root, rev)?;
    require_surface(sources.len(), rev)?;
    let tally: Tally = tally(&sources)?;
    judge(&tally, PINNED_COMMENT_LINES, rev)?;
    println!(
        "xtask comments: {} rust source file(s) at {rev} carry {} own-line `//` comment line(s), \
         the pinned count, and no doc, block, trailing, TODO-class or code-shaped comment",
        sources.len(),
        tally.allowed_lines
    );
    Ok(())
}

fn require_surface(files: usize, rev: &str) -> Result<()> {
    if files < MIN_SOURCES {
        bail!(
            "the rust source surface of {rev} resolved to {files} file(s), fewer than the \
             {MIN_SOURCES} this check requires; a walk that finds almost nothing passes whatever \
             the sources say"
        );
    }
    Ok(())
}

fn tally(sources: &[(String, String)]) -> Result<Tally> {
    let mut tally: Tally = Tally {
        rejected: Vec::new(),
        allowed_lines: 0,
    };
    for (path, text) in sources {
        let reading: Reading = read(path, text);
        if let Some(unclosed) = reading.terminal.unclosed() {
            bail!(
                "the lexer reached the end of {path} still inside {unclosed}, so it lost track \
                 of what is code and what is data in that file. every comment after the point it \
                 desynchronised would go unreported, and a clean result here would mean nothing. \
                 this is a defect in the check, not in the file"
            );
        }
        for comment in reading.comments {
            match comment.verdict() {
                Verdict::Allowed => tally.allowed_lines += 1,
                Verdict::Rejected(reason) => tally.rejected.push(comment.render(reason)),
            }
        }
    }
    Ok(tally)
}

fn judge(tally: &Tally, pinned: usize, rev: &str) -> Result<()> {
    if !tally.rejected.is_empty() {
        bail!(
            "{} rust comment(s) at {rev} take a form the comment rule forbids. only an own-line \
             `//` comment that says why code that looks wrong is right is allowed; doc, block, \
             trailing and `////` comments, TODO-class words and commented-out code are not:\n  {}",
            tally.rejected.len(),
            tally.rejected.join("\n  ")
        );
    }
    if tally.allowed_lines != pinned {
        bail!(
            "the rust sources at {rev} carry {} own-line comment line(s), but xtask/src/comments.rs \
             pins {pinned}. every change to the count is reviewed: pin the new count in the same \
             commit as the comment it adds or removes",
            tally.allowed_lines
        );
    }
    Ok(())
}

fn committed_sources(root: &Path, rev: &str) -> Result<Vec<(String, String)>> {
    let listing: std::process::Output = Command::new("git")
        .current_dir(root)
        .args(["ls-tree", "-r", "-z", "--name-only", rev, "--"])
        .args(SOURCE_TREES)
        .output()
        .wrap_err("listing the rust sources of the commit with git ls-tree")?;
    if !listing.status.success() {
        bail!(
            "git ls-tree {rev} failed: {}",
            String::from_utf8_lossy(&listing.stderr).trim()
        );
    }
    let paths: Vec<String> = listing
        .stdout
        .split(|byte: &u8| *byte == 0)
        .filter(|name: &&[u8]| !name.is_empty())
        .map(|name: &[u8]| String::from_utf8_lossy(name).into_owned())
        .filter(|name: &String| is_rust(name) && !is_skipped(name))
        .collect();
    read_blobs(root, rev, paths)
}

fn read_blobs(root: &Path, rev: &str, paths: Vec<String>) -> Result<Vec<(String, String)>> {
    let mut child: Child = Command::new("git")
        .current_dir(root)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .wrap_err("starting git cat-file --batch")?;
    let mut stdin: ChildStdin = child
        .stdin
        .take()
        .ok_or_else(|| eyre!("git cat-file has no stdin"))?;
    let stdout: ChildStdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre!("git cat-file has no stdout"))?;
    let requests: String = paths
        .iter()
        .fold(String::new(), |mut acc: String, path: &String| {
            acc.push_str(rev);
            acc.push(':');
            acc.push_str(path);
            acc.push('\n');
            acc
        });
    let blobs: Result<Vec<(String, String)>> = std::thread::scope(|scope| {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            stdin.write_all(requests.as_bytes())?;
            drop(stdin);
            Ok(())
        });
        let mut reader: BufReader<ChildStdout> = BufReader::new(stdout);
        let mut blobs: Vec<(String, String)> = Vec::with_capacity(paths.len());
        for path in &paths {
            let mut header: String = String::new();
            reader
                .read_line(&mut header)
                .wrap_err_with(|| format!("reading the git cat-file header for {path}"))?;
            let fields: Vec<&str> = header.split_whitespace().collect();
            let [_, "blob", size] = fields.as_slice() else {
                bail!("git cat-file answered `{}` for {rev}:{path}", header.trim());
            };
            let size: usize = size
                .parse()
                .wrap_err_with(|| format!("git cat-file size for {path}"))?;
            if size > MAX_SOURCE_BYTES {
                bail!("{path} at {rev} is {size} bytes, above the {MAX_SOURCE_BYTES}-byte cap");
            }
            let mut body: Vec<u8> = vec![0; size + 1];
            reader
                .read_exact(&mut body)
                .wrap_err_with(|| format!("reading the blob of {path}"))?;
            body.truncate(size);
            let text: String =
                String::from_utf8(body).map_err(|_| eyre!("{path} at {rev} is not UTF-8"))?;
            blobs.push((path.clone(), text));
        }
        writer
            .join()
            .map_err(|_| eyre!("the git cat-file writer panicked"))?
            .wrap_err("writing requests to git cat-file")?;
        Ok(blobs)
    });
    let status: std::process::ExitStatus = child.wait().wrap_err("waiting for git cat-file")?;
    if !status.success() {
        bail!("git cat-file --batch exited with {status}");
    }
    blobs
}

fn is_skipped(path: &str) -> bool {
    path.split('/')
        .any(|component: &str| SKIPPED_COMPONENTS.contains(&component))
}

fn is_rust(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("rs"))
}

fn read(source: &str, text: &str) -> Reading {
    let chars: Vec<char> = text.chars().collect();
    let lines: Vec<&str> = text.lines().collect();
    let mut comments: Vec<Comment> = Vec::new();
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
                    let after_token: String = chars[index + 2..]
                        .iter()
                        .take_while(|ch: &&char| **ch != '\n')
                        .collect();
                    comments.push(comment(
                        source,
                        &lines,
                        line,
                        column,
                        CommentKind::Line,
                        after_token,
                    ));
                    state = Lexer::LineComment;
                    step = 2;
                } else if current == '/' && next == Some('*') {
                    comments.push(comment(
                        source,
                        &lines,
                        line,
                        column,
                        CommentKind::Block,
                        String::new(),
                    ));
                    state = Lexer::BlockComment(1);
                    step = 2;
                } else if current == '"' {
                    state = Lexer::Text;
                } else if let Some(prefix) = raw_text_prefix(&chars, index) {
                    state = Lexer::RawText(prefix.hashes);
                    step = prefix.width;
                } else if matches!(current, 'b' | 'c')
                    && next == Some('"')
                    && !joins_identifier(&chars, index)
                {
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
        comments,
        terminal: state,
    }
}

#[derive(Debug)]
struct Reading {
    comments: Vec<Comment>,
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
    if matches!(chars.get(cursor), Some('b' | 'c')) {
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

fn comment(
    source: &str,
    lines: &[&str],
    line: usize,
    column: usize,
    kind: CommentKind,
    after_token: String,
) -> Comment {
    let whole: &str = lines.get(line - 1).copied().unwrap_or_default();
    let own_line: bool = whole.chars().take(column - 1).all(char::is_whitespace);
    let text: &str = whole.trim();
    let taken: String = text.chars().take(EXCERPT_CHARS).collect();
    let excerpt: String = if text.chars().count() > EXCERPT_CHARS {
        format!("{taken}...")
    } else {
        taken
    };
    Comment {
        source: source.to_owned(),
        line,
        column,
        kind,
        own_line,
        after_token,
        excerpt,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const SRC: &str = "crates/p/src/lib.rs";

    fn scan(source: &str, text: &str) -> Vec<Comment> {
        read(source, text).comments
    }

    fn tokens(text: &str) -> Vec<(usize, usize, &'static str)> {
        scan(SRC, text)
            .into_iter()
            .map(|c: Comment| {
                let token: &'static str = match c.kind {
                    CommentKind::Line => "//",
                    CommentKind::Block => "/*",
                };
                (c.line, c.column, token)
            })
            .collect()
    }

    fn verdicts(text: &str) -> Vec<Verdict> {
        scan(SRC, text).iter().map(Comment::verdict).collect()
    }

    fn tally_of(text: &str) -> Tally {
        tally(&[(SRC.to_owned(), text.to_owned())]).expect("lexes")
    }

    #[test]
    fn an_own_line_why_comment_is_allowed_and_counted_per_line() {
        let text: &str = "fn f() {\n    // the header stores the length big-endian despite the spec\n    // because every shipped build does\n    g();\n}\n";
        assert_eq!(verdicts(text), vec![Verdict::Allowed, Verdict::Allowed]);
        assert_eq!(tally_of(text).allowed_lines, 2);
    }

    #[test]
    fn an_allowed_comment_passes_only_with_its_count_pinned() {
        let text: &str = "// the loop reads one byte past the header on purpose\nfn f() {}\n";
        let found: Tally = tally_of(text);
        assert!(judge(&found, 1, "HEAD").is_ok());
        let unpinned: String = format!("{:#}", judge(&found, 0, "HEAD").unwrap_err());
        assert!(
            unpinned.contains("carry 1 own-line comment line(s)"),
            "{unpinned}"
        );
        assert!(unpinned.contains("pins 0"), "{unpinned}");
    }

    #[test]
    fn a_stale_pin_fails_in_both_directions() {
        let none: Tally = tally_of("fn f() {}\n");
        assert!(format!("{:#}", judge(&none, 1, "HEAD").unwrap_err()).contains("carry 0"));
        let two: Tally = tally_of("// one\n// two\nfn f() {}\n");
        assert!(format!("{:#}", judge(&two, 1, "HEAD").unwrap_err()).contains("carry 2"));
    }

    #[test]
    fn narration_passes_the_form_rule_and_is_left_to_review_of_the_count() {
        assert_eq!(
            verdicts("// increment the counter\nx += 1;\n"),
            vec![Verdict::Allowed]
        );
    }

    #[test]
    fn todo_class_words_fail_whatever_the_count() {
        for word in BANNED_WORDS {
            let text: String = format!("// {word}: revisit this\nfn f() {{}}\n");
            assert_eq!(
                verdicts(&text),
                vec![Verdict::Rejected("a TODO-class marker")],
                "{word}"
            );
        }
    }

    #[test]
    fn code_shaped_text_fails() {
        for text in [
            "// let x: u8 = 1;\n",
            "// if ready {\n",
            "// }\n",
            "// fn old() -> u8\n",
            "// #[inline]\n",
            "// return x\n",
        ] {
            assert_eq!(
                verdicts(text),
                vec![Verdict::Rejected("code-shaped text")],
                "{text}"
            );
        }
    }

    #[test]
    fn doc_block_trailing_and_quad_slash_comments_fail() {
        assert_eq!(
            verdicts("/// documents f\nfn f() {}\n"),
            vec![Verdict::Rejected("a `///` doc comment")]
        );
        assert_eq!(
            verdicts("//! module note\n"),
            vec![Verdict::Rejected("a `//!` doc comment")]
        );
        assert_eq!(
            verdicts("/* why */\nfn f() {}\n"),
            vec![Verdict::Rejected("a block or block doc comment")]
        );
        assert_eq!(
            verdicts("/** doc */\nfn f() {}\n"),
            vec![Verdict::Rejected("a block or block doc comment")]
        );
        assert_eq!(
            verdicts("let x: u8 = 1; // trailing why\n"),
            vec![Verdict::Rejected("a trailing comment")]
        );
        assert_eq!(
            verdicts("//// banner\n"),
            vec![Verdict::Rejected("a `////` comment")]
        );
    }

    #[test]
    fn comment_tokens_inside_every_literal_form_are_data() {
        let text: &str = concat!(
            "const A: &str = \"// s\";\n",
            "const B: &str = r#\"// r\"#;\n",
            "const C: &[u8] = b\"// b\";\n",
            "const D: &[u8] = br#\"/* br */\"#;\n",
            "const E: &std::ffi::CStr = c\"// c\";\n",
            "const F: &std::ffi::CStr = cr#\"// cr \"inner\" \"#;\n",
        );
        assert!(scan(SRC, text).is_empty(), "{:?}", scan(SRC, text));
        assert_eq!(read(SRC, text).terminal.unclosed(), None);
    }

    #[test]
    fn a_line_comment_is_reported_with_its_position() {
        assert_eq!(
            tokens("let x: u8 = 1;\n    // stray note\n"),
            vec![(2, 5, "//")]
        );
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
    fn a_desynchronised_file_fails_the_tally_instead_of_passing_silently() {
        let sources: Vec<(String, String)> = vec![
            (SRC.to_owned(), "fn f() {}\n".to_owned()),
            (
                "crates/p/src/bad.rs".to_owned(),
                "let s: &str = \"never closed\n/// swallowed\n".to_owned(),
            ),
        ];
        let error: String = tally(&sources)
            .expect_err("a desynchronised lexer must fail the tally")
            .to_string();
        assert!(error.contains("crates/p/src/bad.rs"), "{error}");
        assert!(error.contains("a string literal"), "{error}");
    }

    #[test]
    fn a_surface_below_the_file_floor_fails_and_the_floor_itself_passes() {
        let error: String = require_surface(MIN_SOURCES - 1, "HEAD")
            .expect_err("one file short of the floor must fail")
            .to_string();
        assert!(
            error.contains(&format!("{} file(s)", MIN_SOURCES - 1)),
            "{error}"
        );
        assert!(require_surface(0, "HEAD").is_err());
        assert!(require_surface(MIN_SOURCES, "HEAD").is_ok());
    }

    #[test]
    fn the_rejection_quotes_the_line_it_found() {
        let found: Vec<Comment> = scan(SRC, "fn f() {}\n  /// documents nothing\n");
        assert_eq!(found.len(), 1, "{found:?}");
        let rendered: String = found[0].render("a `///` doc comment");
        assert!(
            rendered.starts_with("crates/p/src/lib.rs:2:3"),
            "{rendered}"
        );
        assert!(rendered.contains("documents nothing"), "{rendered}");
    }

    #[test]
    fn the_verdict_reads_the_commit_not_the_working_tree() -> Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let git = |args: &[&str]| -> Result<()> {
            let status: std::process::ExitStatus = Command::new("git")
                .current_dir(root.path())
                .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
                .args(args)
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err(eyre!("git {args:?} failed"))
            }
        };
        git(&["init", "-q"])?;
        std::fs::create_dir_all(root.path().join("crates/p/src"))?;
        std::fs::write(root.path().join("crates/p/src/lib.rs"), "fn f() {}\n")?;
        git(&["add", "crates"])?;
        git(&["commit", "-q", "-m", "probe"])?;
        std::fs::write(
            root.path().join("crates/p/src/lib.rs"),
            "/// added after the commit\nfn f() {}\n",
        )?;
        let sources: Vec<(String, String)> = committed_sources(root.path(), "HEAD")?;
        assert_eq!(
            sources,
            vec![("crates/p/src/lib.rs".to_owned(), "fn f() {}\n".to_owned())]
        );
        let found: Tally = tally(&sources)?;
        assert!(judge(&found, 0, "HEAD").is_ok());
        Ok(())
    }
}
