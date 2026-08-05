use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::fileio::read_text_bounded;

const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;

const ROOT_DOCUMENTS: [&str; 3] = ["README.md", "LEGAL.md", "SECURITY.md"];

const EXCLUDED_DOCUMENTS: [(&str, &str); 6] = [
    (
        "crates/disrobe-sleigh/vendor/aarch64/ATTRIBUTION.md",
        "vendored third-party attribution text that must stay verbatim",
    ),
    (
        "crates/disrobe-sleigh/vendor/arm/ATTRIBUTION.md",
        "vendored third-party attribution text that must stay verbatim",
    ),
    (
        "crates/disrobe-sleigh/vendor/mips/ATTRIBUTION.md",
        "vendored third-party attribution text that must stay verbatim",
    ),
    (
        "crates/disrobe-sleigh/vendor/powerpc/ATTRIBUTION.md",
        "vendored third-party attribution text that must stay verbatim",
    ),
    (
        "crates/disrobe-sleigh/vendor/riscv/ATTRIBUTION.md",
        "vendored third-party attribution text that must stay verbatim",
    ),
    (
        "corpus/binfmt/wim/files_expected/readme.md",
        "corpus fixture whose bytes crates/disrobe-binfmt/tests/real_wim_files.rs compares",
    ),
];

const MIN_DOCUMENTS: usize = 300;

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
const EXCLAMATION_RULE: &str = "an exclamation mark";

#[derive(Debug)]
struct Finding {
    document: String,
    line: usize,
    column: usize,
    rule: String,
    excerpt: String,
}

#[derive(Debug, serde::Deserialize)]
struct VoiceClass {
    rule: String,
    tokens: Vec<String>,
}

#[derive(Debug, Default)]
struct VoiceRules {
    classes: Vec<VoiceClass>,
}

impl VoiceRules {
    fn load(root: &Path) -> Result<Self> {
        let path: PathBuf = root.join("xtask").join("data").join("voice.toml");
        let text: String = read_text_bounded(&path, MAX_DOCUMENT_BYTES)
            .wrap_err_with(|| format!("reading the voice rule file {}", path.display()))?;
        let table: toml::Table = toml::from_str(&text)
            .wrap_err_with(|| format!("parsing the voice rule file {}", path.display()))?;
        let mut classes: Vec<VoiceClass> = Vec::new();
        for (name, value) in table {
            if name == "rules_version" {
                continue;
            }
            let class: VoiceClass = value.try_into().wrap_err_with(|| {
                format!("voice rule class {name} needs a rule and a tokens list")
            })?;
            if class.tokens.is_empty() {
                bail!("voice rule class {name} declares no tokens, so it can never fire");
            }
            for token in &class.tokens {
                if token.trim().is_empty() || token != &token.to_ascii_lowercase() {
                    bail!(
                        "voice rule token {token:?} in class {name} must be non-empty and lowercase, because matching folds case"
                    );
                }
            }
            classes.push(class);
        }
        if classes.is_empty() {
            bail!("the voice rule file declares no classes, so this gate would pass on anything");
        }
        Ok(Self { classes })
    }

    fn token_count(&self) -> usize {
        self.classes
            .iter()
            .map(|c: &VoiceClass| c.tokens.len())
            .sum()
    }

    fn findings(&self, document: &str, number: usize, scanned: &str, raw: &str) -> Vec<Finding> {
        let lowered: String = scanned.to_ascii_lowercase();
        let mut out: Vec<Finding> = Vec::new();
        for class in &self.classes {
            for token in &class.tokens {
                let Some(at) = word_bounded_find(&lowered, token) else {
                    continue;
                };
                out.push(Finding {
                    document: document.to_owned(),
                    line: number,
                    column: at + 1,
                    rule: class.rule.clone(),
                    excerpt: excerpt(raw),
                });
            }
        }
        out
    }
}

fn word_bounded_find(haystack: &str, needle: &str) -> Option<usize> {
    let bytes: &[u8] = haystack.as_bytes();
    let width: usize = needle.len();
    let mut from: usize = 0usize;
    while let Some(offset) = haystack
        .get(from..)
        .and_then(|rest: &str| rest.find(needle))
    {
        let at: usize = from + offset;
        let before_ok: bool = at == 0 || !is_word_byte(bytes[at - 1]);
        let after: usize = at + width;
        let after_ok: bool = after >= bytes.len() || !is_word_byte(bytes[after]);
        if before_ok && after_ok {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

fn is_prose_exclamation(line: &str, column: usize) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let Some(previous) = column.checked_sub(1).and_then(|at: usize| chars.get(at)) else {
        return false;
    };
    if !previous.is_alphanumeric() && *previous != ')' && *previous != '"' {
        return false;
    }
    chars
        .get(column + 1)
        .is_none_or(|next: &char| next.is_whitespace() || *next == '"')
}

const fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
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
    let rules: VoiceRules = VoiceRules::load(root)?;
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
        for finding in scan(&relative, &text, &rules) {
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
        "xtask regen: {} tracked markdown document(s), every one git tracks except {} named \
         exclusions, carry no long dash, no double hyphen standing in for one, no emoji, no \
         prose exclamation mark, and none of the {} voice tokens in xtask/data/voice.toml",
        documents.len(),
        EXCLUDED_DOCUMENTS.len(),
        rules.token_count()
    );
    Ok(())
}

fn surface(root: &Path) -> Result<Vec<PathBuf>> {
    for name in ROOT_DOCUMENTS {
        if !root.join(name).is_file() {
            bail!(
                "{name} is a published surface this check reads, but it is missing from {}, so the \
                 document a reader meets first would go unread",
                root.display()
            );
        }
    }
    let output: std::process::Output = std::process::Command::new("git")
        .args(["ls-files", "-z", "--", "*.md"])
        .current_dir(root)
        .output()
        .wrap_err("listing tracked markdown with git")?;
    if !output.status.success() {
        bail!(
            "git ls-files exited with {} in {}",
            output.status,
            root.display()
        );
    }
    let listing: String =
        String::from_utf8(output.stdout).wrap_err("git ls-files output is not utf-8")?;
    let mut documents: Vec<PathBuf> = Vec::new();
    let mut excluded: usize = 0usize;
    for rel in listing.split('\0').filter(|s: &&str| !s.is_empty()) {
        if EXCLUDED_DOCUMENTS
            .iter()
            .any(|(path, _)| rel.eq_ignore_ascii_case(path))
        {
            excluded += 1;
            continue;
        }
        documents.push(root.join(rel));
    }
    if excluded != EXCLUDED_DOCUMENTS.len() {
        bail!(
            "the voice gate excludes {} document(s) by name but only {excluded} of them are tracked; \
             an exclusion that no longer matches a real file silently widens or narrows the scan, so \
             update EXCLUDED_DOCUMENTS in xtask/src/typography.rs",
            EXCLUDED_DOCUMENTS.len()
        );
    }
    documents.sort();
    documents.dedup();
    Ok(documents)
}

fn scan(document: &str, text: &str, rules: &VoiceRules) -> Vec<Finding> {
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
            } else if ch == '!' && is_prose_exclamation(&scanned, column) {
                EXCLAMATION_RULE
            } else {
                continue;
            };
            findings.push(Finding {
                document: document.to_owned(),
                line: number,
                column: column + 1,
                rule: rule.to_owned(),
                excerpt: excerpt(line),
            });
        }
        if let Some(column) = typed_dash_column(&scanned) {
            findings.push(Finding {
                document: document.to_owned(),
                line: number,
                column,
                rule: TYPED_DASH_RULE.to_owned(),
                excerpt: excerpt(line),
            });
        }
        findings.extend(rules.findings(document, number, &scanned, line));
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

    fn rules() -> VoiceRules {
        VoiceRules::default()
    }

    fn loaded_rules() -> VoiceRules {
        VoiceRules {
            classes: vec![VoiceClass {
                rule: "a filler word that says nothing".to_owned(),
                tokens: vec!["utilize".to_owned(), "out of the box".to_owned()],
            }],
        }
    }

    #[test]
    fn a_filler_token_in_prose_is_reported() {
        let findings: Vec<Finding> = scan(DOC, "we utilize the quota machinery\n", &loaded_rules());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, "a filler word that says nothing");
    }

    #[test]
    fn a_filler_token_inside_a_longer_word_is_not_reported() {
        assert!(scan(DOC, "the utilizer struct is fine\n", &loaded_rules()).is_empty());
    }

    #[test]
    fn a_prose_exclamation_is_reported() {
        let findings: Vec<Finding> = scan(DOC, "it recovered everything!\n", &rules());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, EXCLAMATION_RULE);
    }

    #[test]
    fn a_marker_span_and_an_image_are_not_exclamations() {
        assert!(scan(DOC, "<!-- m:key -->96.6%<!-- /m --> per object\n", &rules()).is_empty());
        assert!(scan(DOC, "![demo](docs/demo.svg)\n", &rules()).is_empty());
    }

    #[test]
    fn an_em_dash_in_prose_is_reported() {
        let findings: Vec<Finding> = scan(
            DOC,
            "recovery is bounded \u{2014} by the artifact\n",
            &rules(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, LONG_DASH_RULE);
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].column, 21);
    }

    #[test]
    fn an_en_dash_is_reported_by_the_same_rule() {
        let findings: Vec<Finding> = scan(DOC, "CPython 3.0\u{2013}3.15\n", &rules());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, LONG_DASH_RULE);
    }

    #[test]
    fn an_emoji_in_prose_is_reported() {
        let findings: Vec<Finding> = scan(DOC, "every gate is green \u{2705}\n", &rules());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, EMOJI_RULE);
    }

    #[test]
    fn a_double_hyphen_standing_in_for_a_dash_is_reported() {
        let findings: Vec<Finding> =
            scan(DOC, "the gap -- the whole point -- is stated\n", &rules());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, TYPED_DASH_RULE);
        assert_eq!(findings[0].column, 9);
    }

    #[test]
    fn a_command_flag_inside_a_code_span_is_not_a_dash() {
        let findings: Vec<Finding> = scan(
            DOC,
            "run `cargo run -p xtask -- regen --check` first\n",
            &rules(),
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_fenced_block_may_carry_a_double_hyphen() {
        let text: &str =
            "prose\n```sh\ncargo test -p disrobe-cli -- --nocapture\n```\nmore prose\n";
        assert!(scan(DOC, text, &rules()).is_empty());
    }

    #[test]
    fn a_dash_after_an_unterminated_code_span_is_still_reported() {
        let findings: Vec<Finding> =
            scan(DOC, "a stray ` backtick then \u{2014} a dash\n", &rules());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, LONG_DASH_RULE);
    }

    #[test]
    fn box_drawing_characters_are_not_emoji() {
        let text: &str = "   Raw  \u{2500}\u{2500}\u{25b2}  Disasm\n";
        assert!(scan("docs/src/ir-ladder.md", text, &rules()).is_empty());
    }

    #[test]
    fn a_hyphenated_range_and_a_flag_in_prose_are_not_dashes() {
        let text: &str = "CPython 1.0-3.15 recovers, and --allow-dynamic gates the rest.\n";
        assert!(scan(DOC, text, &rules()).is_empty());
    }

    #[test]
    fn a_copyright_sign_is_not_an_emoji() {
        assert!(
            scan(
                "LEGAL.md",
                "\u{a9} 2026 Latency LLC, all rights reserved\n",
                &rules()
            )
            .is_empty()
        );
    }

    #[test]
    fn a_finding_names_the_document_the_line_and_the_text() {
        let findings: Vec<Finding> =
            scan("docs/src/python.md", "one\ntwo \u{2014} three\n", &rules());
        assert_eq!(findings.len(), 1, "{findings:?}");
        let rendered: String = findings[0].render();
        assert!(rendered.starts_with("docs/src/python.md:2:5"), "{rendered}");
        assert!(rendered.contains("three"), "{rendered}");
    }

    #[test]
    fn a_long_excerpt_is_truncated_rather_than_printed_whole() {
        let line: String = "x".repeat(EXCERPT_CHARS + 10);
        let text: String = format!("{line}\u{2014}\n");
        let findings: Vec<Finding> = scan(DOC, &text, &rules());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].excerpt.ends_with("..."), "{findings:?}");
    }
}
