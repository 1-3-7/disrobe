use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};
use serde::Deserialize;

use crate::fileio::read_text_bounded;

const MAX_RECOVERY_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DOC_BYTES: u64 = 8 * 1024 * 1024;

const OPEN_PREFIX: &str = "<!-- m:";
const OPEN_SUFFIX: &str = " -->";
const CLOSE: &str = "<!-- /m -->";
const IGNORE_MARKER: &str = "<!-- m:ignore -->";

/// Whether `metrics` rewrites the markered docs or only verifies them.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Mode {
    Write,
    Check,
}

#[derive(Debug, Deserialize)]
struct Recovery {
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize)]
struct Group {
    heading: String,
    bars: Vec<Bar>,
}

#[derive(Debug, Deserialize)]
struct Bar {
    label: String,
    #[serde(default)]
    value: Option<f64>,
    #[serde(default)]
    detected: Option<u64>,
    #[serde(default)]
    delivered: Option<u64>,
}

impl Recovery {
    fn bar(&self, heading_substr: &str, label: &str) -> Result<&Bar> {
        for group in &self.groups {
            if group.heading.contains(heading_substr) {
                for bar in &group.bars {
                    if bar.label == label {
                        return Ok(bar);
                    }
                }
            }
        }
        bail!("recovery.json has no bar `{label}` under a heading containing `{heading_substr}`")
    }
}

impl Bar {
    fn percent(&self) -> Result<MetricValue> {
        let raw: f64 = self
            .value
            .ok_or_else(|| eyre!("bar `{}` has no percent value", self.label))?;
        Ok(MetricValue::Percent(raw))
    }

    fn count(&self) -> Result<MetricValue> {
        let raw: f64 = self
            .value
            .ok_or_else(|| eyre!("bar `{}` has no count value", self.label))?;
        Ok(MetricValue::Int(f64_to_u64_exact(raw, &self.label)?))
    }

    fn delivered(&self) -> Result<u64> {
        self.delivered
            .ok_or_else(|| eyre!("bar `{}` has no delivered count", self.label))
    }

    fn detected(&self) -> Result<u64> {
        self.detected
            .ok_or_else(|| eyre!("bar `{}` has no detected count", self.label))
    }
}

#[derive(Debug, Clone, Copy)]
enum MetricValue {
    Int(u64),
    Ratio { num: u64, den: u64 },
    Percent(f64),
}

#[derive(Debug, Clone, Copy)]
enum Formatter {
    Int,
    Thousands,
    Pct,
    Frac,
}

impl Formatter {
    fn render(self, value: MetricValue) -> Result<String> {
        match (self, value) {
            (Self::Int, MetricValue::Int(n)) => Ok(n.to_string()),
            (Self::Thousands, MetricValue::Int(n)) => Ok(group_thousands(n)),
            (Self::Pct, MetricValue::Percent(p)) => Ok(format_percent(p)),
            (Self::Frac, MetricValue::Ratio { num, den }) => Ok(format!("{num} / {den}")),
            (formatter, other) => {
                bail!("formatter {formatter:?} cannot render metric value {other:?}")
            }
        }
    }
}

struct KeySpec {
    name: &'static str,
    formatter: Formatter,
    nouns: &'static [&'static str],
    extract: fn(&Recovery) -> Result<MetricValue>,
}

const KEYS: &[KeySpec] = &[
    KeySpec {
        name: "py_stdlib_full_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "full 571-module stdlib (representative)")?
                .percent()
        },
    },
    KeySpec {
        name: "py_stdlib_pinned_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "200-module pinned corpus")?
                .percent()
        },
    },
    KeySpec {
        name: "py_legacy_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| r.bar("CPython legacy", "proven-correct")?.percent(),
    },
    KeySpec {
        name: "go_typename_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| r.bar("Go type-name", "type names")?.percent(),
    },
    KeySpec {
        name: "dalvik_verifier_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Dalvik recovered bodies", "verifier-clean (committed, CI)")?
                .percent()
        },
    },
    KeySpec {
        name: "dalvik_body_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "Dalvik recovered bodies",
                "body-lowering (real apks, local)",
            )?
            .percent()
        },
    },
    KeySpec {
        name: "ruby_greeter_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| r.bar("Ruby YARV", "greeter")?.percent(),
    },
    KeySpec {
        name: "ruby_megafile_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| r.bar("Ruby YARV", "megafile")?.percent(),
    },
    KeySpec {
        name: "dotnet_protectors",
        formatter: Formatter::Int,
        nouns: &["protectors", "protector"],
        extract: |r: &Recovery| {
            Ok(MetricValue::Int(
                r.bar("Detection and extraction breadth", ".NET protectors")?
                    .detected()?,
            ))
        },
    },
    KeySpec {
        name: "pyarmor_samples",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            Ok(MetricValue::Int(
                r.bar("Detection and extraction breadth", "PyArmor samples")?
                    .delivered()?,
            ))
        },
    },
    KeySpec {
        name: "pyarmor_frac",
        formatter: Formatter::Frac,
        nouns: &[],
        extract: |r: &Recovery| {
            let bar: &Bar = r.bar("Detection and extraction breadth", "PyArmor samples")?;
            Ok(MetricValue::Ratio {
                num: bar.delivered()?,
                den: bar.detected()?,
            })
        },
    },
    KeySpec {
        name: "containers_formats",
        formatter: Formatter::Int,
        nouns: &["formats"],
        extract: |r: &Recovery| {
            Ok(MetricValue::Int(
                r.bar("Detection and extraction breadth", "Containers")?
                    .delivered()?,
            ))
        },
    },
    KeySpec {
        name: "containers_frac",
        formatter: Formatter::Frac,
        nouns: &[],
        extract: |r: &Recovery| {
            let bar: &Bar = r.bar("Detection and extraction breadth", "Containers")?;
            Ok(MetricValue::Ratio {
                num: bar.delivered()?,
                den: bar.detected()?,
            })
        },
    },
    KeySpec {
        name: "js_bundlers",
        formatter: Formatter::Int,
        nouns: &["bundlers"],
        extract: |r: &Recovery| {
            r.bar("Obfuscator and bundler family coverage", "JS bundlers")?
                .count()
        },
    },
    KeySpec {
        name: "lua_catalog_entries",
        formatter: Formatter::Int,
        nouns: &["catalog entries"],
        extract: |r: &Recovery| {
            r.bar(
                "Obfuscator and bundler family coverage",
                "Lua chain catalog entries",
            )?
            .count()
        },
    },
    KeySpec {
        name: "wasm_reversers",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "Obfuscator and bundler family coverage",
                "WASM obfuscator reversers",
            )?
            .count()
        },
    },
    KeySpec {
        name: "hermes_functions",
        formatter: Formatter::Thousands,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "React Native Hermes production-bundle parse scale",
                "functions parsed",
            )?
            .count()
        },
    },
];

fn spec_for(name: &str) -> Option<&'static KeySpec> {
    KEYS.iter().find(|spec: &&KeySpec| spec.name == name)
}

fn collect_nouns() -> Vec<&'static str> {
    let mut nouns: Vec<&'static str> = Vec::new();
    for spec in KEYS {
        for noun in spec.nouns {
            if !nouns.contains(noun) {
                nouns.push(noun);
            }
        }
    }
    nouns.sort_unstable_by(|a: &&str, b: &&str| b.len().cmp(&a.len()).then(a.cmp(b)));
    nouns
}

#[derive(Debug)]
struct MarkerSpan {
    name: String,
    line: usize,
    content: String,
    content_start: usize,
    content_end: usize,
}

fn parse_spans(text: &str, suppressed: &mut Vec<usize>) -> Result<Vec<MarkerSpan>> {
    let mut spans: Vec<MarkerSpan> = Vec::new();
    let mut in_fence: bool = false;
    let mut offset: usize = 0;
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let line_no: usize = idx + 1;
        let trimmed: &str = line.trim_start();
        let is_fence_delim: bool = trimmed.starts_with("```") || trimmed.starts_with("~~~");
        scan_line(line, line_no, offset, in_fence, &mut spans, suppressed)?;
        if is_fence_delim {
            in_fence = !in_fence;
        }
        offset += line.len();
    }
    Ok(spans)
}

fn scan_line(
    line: &str,
    line_no: usize,
    line_offset: usize,
    in_fence: bool,
    spans: &mut Vec<MarkerSpan>,
    suppressed: &mut Vec<usize>,
) -> Result<()> {
    let mut search_from: usize = 0;
    while let Some(rel) = line[search_from..].find(OPEN_PREFIX) {
        let open_at: usize = search_from + rel;
        if line[open_at..].starts_with(IGNORE_MARKER) {
            if !suppressed.contains(&line_no) {
                suppressed.push(line_no);
            }
            search_from = open_at + IGNORE_MARKER.len();
            continue;
        }
        let after_prefix: usize = open_at + OPEN_PREFIX.len();
        let Some(suffix_rel) = line[after_prefix..].find(OPEN_SUFFIX) else {
            bail!(
                "line {line_no}: marker opening `{OPEN_PREFIX}` has no closing `{OPEN_SUFFIX}` on the same line (unclosed or multi-line span)"
            );
        };
        let key_name: &str = &line[after_prefix..after_prefix + suffix_rel];
        let content_from: usize = after_prefix + suffix_rel + OPEN_SUFFIX.len();
        let Some(close_rel) = line[content_from..].find(CLOSE) else {
            bail!(
                "line {line_no}: marker span for `m:{key_name}` has no `{CLOSE}` on the same line (unclosed or multi-line span)"
            );
        };
        let content_end: usize = content_from + close_rel;
        let content: &str = &line[content_from..content_end];
        if content.contains(OPEN_PREFIX) {
            bail!("line {line_no}: marker span for `m:{key_name}` contains a nested marker");
        }
        if in_fence {
            bail!("line {line_no}: marker `m:{key_name}` sits inside a fenced code block");
        }
        if spec_for(key_name).is_none() {
            bail!("line {line_no}: unknown metric key `m:{key_name}`");
        }
        spans.push(MarkerSpan {
            name: key_name.to_owned(),
            line: line_no,
            content: content.to_owned(),
            content_start: line_offset + content_from,
            content_end: line_offset + content_end,
        });
        search_from = content_end + CLOSE.len();
    }
    Ok(())
}

fn rewrite_text(text: &str, recovery: &Recovery) -> Result<String> {
    let mut suppressed: Vec<usize> = Vec::new();
    let spans: Vec<MarkerSpan> = parse_spans(text, &mut suppressed)?;
    if spans.is_empty() {
        return Ok(text.to_owned());
    }
    let mut out: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    for span in &spans {
        let Some(spec) = spec_for(&span.name) else {
            bail!("line {}: unknown metric key `m:{}`", span.line, span.name);
        };
        let value: MetricValue = (spec.extract)(recovery)
            .wrap_err_with(|| format!("extracting metric `{}`", span.name))?;
        let rendered: String = spec.formatter.render(value)?;
        out.push_str(&text[cursor..span.content_start]);
        out.push_str(&rendered);
        cursor = span.content_end;
    }
    out.push_str(&text[cursor..]);
    Ok(out)
}

fn check_text(
    text: &str,
    recovery: &Recovery,
    label: &str,
    issues: &mut Vec<String>,
) -> Result<()> {
    let mut suppressed: Vec<usize> = Vec::new();
    let spans: Vec<MarkerSpan> = parse_spans(text, &mut suppressed)
        .wrap_err_with(|| format!("parsing marker spans in {label}"))?;
    for span in &spans {
        let Some(spec) = spec_for(&span.name) else {
            issues.push(format!(
                "{label}:{}: unknown metric key `m:{}`",
                span.line, span.name
            ));
            continue;
        };
        let value: MetricValue = (spec.extract)(recovery)
            .wrap_err_with(|| format!("extracting metric `{}`", span.name))?;
        let expected: String = spec.formatter.render(value)?;
        if span.content != expected {
            issues.push(format!(
                "{label}:{}: marker `m:{}` expected `{expected}` found `{}`",
                span.line, span.name, span.content
            ));
        }
    }
    backstop(text, &spans, &suppressed, label, issues);
    Ok(())
}

fn backstop(
    text: &str,
    spans: &[MarkerSpan],
    suppressed: &[usize],
    label: &str,
    issues: &mut Vec<String>,
) {
    let nouns: Vec<&'static str> = collect_nouns();
    if nouns.is_empty() {
        return;
    }
    let bytes: &[u8] = text.as_bytes();
    let mut in_fence: bool = false;
    let mut offset: usize = 0;
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let line_no: usize = idx + 1;
        let trimmed: &str = line.trim_start();
        let is_fence_delim: bool = trimmed.starts_with("```") || trimmed.starts_with("~~~");
        if !in_fence && !is_fence_delim && !suppressed.contains(&line_no) {
            scan_backstop_line(line, offset, bytes, &nouns, spans, label, line_no, issues);
        }
        if is_fence_delim {
            in_fence = !in_fence;
        }
        offset += line.len();
    }
}

fn scan_backstop_line(
    line: &str,
    line_offset: usize,
    file_bytes: &[u8],
    nouns: &[&'static str],
    spans: &[MarkerSpan],
    label: &str,
    line_no: usize,
    issues: &mut Vec<String>,
) {
    let raw: &[u8] = line.as_bytes();
    let mut idx: usize = 0;
    while idx < raw.len() {
        if !raw[idx].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start_abs: usize = line_offset + idx;
        if is_word_byte(prev_byte(file_bytes, start_abs)) {
            idx += 1;
            continue;
        }
        let mut end: usize = idx;
        while end < raw.len() && is_number_byte(raw[end]) {
            end += 1;
        }
        let mut noun_at: usize = end;
        while noun_at < raw.len() && (raw[noun_at] == b' ' || raw[noun_at] == b'\t') {
            noun_at += 1;
        }
        if let Some(noun) = matching_noun(&line[noun_at..], nouns) {
            let covered: bool = spans.iter().any(|span: &MarkerSpan| {
                start_abs >= span.content_start && start_abs < span.content_end
            });
            if !covered {
                let digits: &str = &line[idx..end];
                issues.push(format!(
                    "{label}:{line_no}: bare number `{digits}` before unit noun `{noun}` is not inside a marker span (wrap it in `{OPEN_PREFIX}KEY{OPEN_SUFFIX}...{CLOSE}` or add `{IGNORE_MARKER}` to the line)"
                ));
            }
        }
        idx = end.max(idx + 1);
    }
}

fn matching_noun(rest: &str, nouns: &[&'static str]) -> Option<&'static str> {
    let rest_bytes: &[u8] = rest.as_bytes();
    for noun in nouns {
        if rest.starts_with(noun) {
            let after: Option<u8> = rest_bytes.get(noun.len()).copied();
            if !is_word_byte(after) {
                return Some(noun);
            }
        }
    }
    None
}

const fn prev_byte(bytes: &[u8], at: usize) -> Option<u8> {
    if at == 0 { None } else { Some(bytes[at - 1]) }
}

const fn is_word_byte(byte: Option<u8>) -> bool {
    match byte {
        Some(b) => b.is_ascii_alphanumeric() || b == b'_',
        None => false,
    }
}

const fn is_number_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b',' | b'.' | b'/' | b'%')
}

fn format_percent(percent: f64) -> String {
    let raw: String = format!("{percent:.6}");
    let trimmed: &str = raw.trim_end_matches('0').trim_end_matches('.');
    format!("{trimmed}%")
}

fn group_thousands(value: u64) -> String {
    let digits: String = value.to_string();
    let len: usize = digits.len();
    let mut out: String = String::with_capacity(len + len / 3);
    for (idx, ch) in digits.chars().enumerate() {
        if idx > 0 && (len - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn f64_to_u64_exact(value: f64, label: &str) -> Result<u64> {
    if !value.is_finite() || value < 0.0 || value.fract() > f64::EPSILON {
        bail!("bar `{label}` value {value} is not a non-negative integer");
    }
    Ok(value as u64)
}

fn manifest(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = vec![root.join("README.md")];
    let docs_src: PathBuf = root.join("docs").join("src");
    if docs_src.is_dir() {
        for entry in walkdir::WalkDir::new(&docs_src) {
            let dirent: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", docs_src.display()))?;
            let path: &Path = dirent.path();
            if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("md") {
                files.push(path.to_path_buf());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn load_recovery(root: &Path) -> Result<Recovery> {
    let path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let raw: String = read_text_bounded(&path, MAX_RECOVERY_JSON_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).wrap_err_with(|| format!("parsing {}", path.display()))
}

pub(crate) fn run(root: &Path, mode: Mode) -> Result<()> {
    let recovery: Recovery = load_recovery(root)?;
    let files: Vec<PathBuf> = manifest(root)?;
    match mode {
        Mode::Write => {
            let mut rewritten: usize = 0;
            for path in &files {
                let text: String = read_text_bounded(path, MAX_DOC_BYTES)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let updated: String = rewrite_text(&text, &recovery)
                    .wrap_err_with(|| format!("rewriting markers in {}", path.display()))?;
                if updated != text {
                    std::fs::write(path, &updated)
                        .wrap_err_with(|| format!("writing {}", path.display()))?;
                    rewritten += 1;
                }
            }
            println!(
                "xtask metrics: {rewritten} file(s) rewritten across {} manifest file(s)",
                files.len()
            );
            Ok(())
        }
        Mode::Check => {
            let mut issues: Vec<String> = Vec::new();
            for path in &files {
                let text: String = read_text_bounded(path, MAX_DOC_BYTES)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let label: String = display_label(root, path);
                check_text(&text, &recovery, &label, &mut issues)?;
            }
            if issues.is_empty() {
                println!(
                    "xtask metrics --check: every marker span and unit-noun number across {} file(s) matches xtask/data/recovery.json",
                    files.len()
                );
                Ok(())
            } else {
                bail!(
                    "documentation metric markers are stale or bare; run `cargo run -p xtask -- metrics --write`:\n  {}",
                    issues.join("\n  ")
                )
            }
        }
    }
}

fn display_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_recovery() -> Result<Recovery> {
        let raw: &str = r#"{
            "groups": [
                {
                    "heading": "Detection and extraction breadth (counts, not percentages)",
                    "bars": [
                        {"label": ".NET protectors", "detected": 23, "delivered": 3},
                        {"label": "PyArmor samples", "detected": 72, "delivered": 72},
                        {"label": "Containers", "detected": 98, "delivered": 98}
                    ]
                },
                {
                    "heading": "Python bytecode (CPython 3.14 stdlib)",
                    "bars": [
                        {"label": "full 571-module stdlib (representative)", "value": 92.43},
                        {"label": "200-module pinned corpus", "value": 94.18}
                    ]
                },
                {
                    "heading": "React Native Hermes production-bundle parse scale",
                    "bars": [
                        {"label": "functions parsed", "value": 122633}
                    ]
                }
            ]
        }"#;
        serde_json::from_str(raw).map_err(|err| eyre!("{err}"))
    }

    #[test]
    fn percent_formatter_strips_trailing_zeros() {
        assert_eq!(format_percent(92.43), "92.43%");
        assert_eq!(format_percent(94.18), "94.18%");
        assert_eq!(format_percent(92.5), "92.5%");
        assert_eq!(format_percent(85.0), "85%");
        assert_eq!(format_percent(100.0), "100%");
    }

    #[test]
    fn thousands_formatter_groups() {
        assert_eq!(group_thousands(122_633), "122,633");
        assert_eq!(group_thousands(98), "98");
        assert_eq!(group_thousands(1_000), "1,000");
    }

    #[test]
    fn write_is_a_fixpoint() -> Result<()> {
        let recovery: Recovery = test_recovery()?;
        let source: &str = "we detect <!-- m:dotnet_protectors -->0<!-- /m --> protector families, \
             <!-- m:containers_frac -->1 / 1<!-- /m --> formats, and \
             <!-- m:hermes_functions -->0<!-- /m -->-function bundles.\n";
        let once: String = rewrite_text(source, &recovery)?;
        let twice: String = rewrite_text(&once, &recovery)?;
        assert!(once.contains("-->23<!-- /m --> protector families"));
        assert!(once.contains("-->98 / 98<!-- /m --> formats"));
        assert!(once.contains("-->122,633<!-- /m -->-function"));
        assert_eq!(once, twice);
        Ok(())
    }

    #[test]
    fn check_passes_after_write() -> Result<()> {
        let recovery: Recovery = test_recovery()?;
        let source: &str =
            "we detect <!-- m:dotnet_protectors -->0<!-- /m --> protector families.\n";
        let written: String = rewrite_text(source, &recovery)?;
        let mut issues: Vec<String> = Vec::new();
        check_text(&written, &recovery, "fixture.md", &mut issues)?;
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
        Ok(())
    }

    #[test]
    fn check_flags_a_bare_unit_noun_number() -> Result<()> {
        let recovery: Recovery = test_recovery()?;
        let source: &str = "we detect 23 protectors here.\n";
        let mut issues: Vec<String> = Vec::new();
        check_text(source, &recovery, "fixture.md", &mut issues)?;
        assert_eq!(
            issues.len(),
            1,
            "expected one bare-number issue: {issues:?}"
        );
        Ok(())
    }

    #[test]
    fn ignore_marker_suppresses_the_backstop() -> Result<()> {
        let recovery: Recovery = test_recovery()?;
        let source: &str = "legacy note: 23 protectors from another era. <!-- m:ignore -->\n";
        let mut issues: Vec<String> = Vec::new();
        check_text(source, &recovery, "fixture.md", &mut issues)?;
        assert!(issues.is_empty(), "ignore should suppress: {issues:?}");
        Ok(())
    }

    #[test]
    fn check_flags_a_stale_marker_value() -> Result<()> {
        let recovery: Recovery = test_recovery()?;
        let source: &str = "detect <!-- m:dotnet_protectors -->21<!-- /m --> protectors.\n";
        let mut issues: Vec<String> = Vec::new();
        check_text(source, &recovery, "fixture.md", &mut issues)?;
        assert_eq!(issues.len(), 1, "expected a stale-value issue: {issues:?}");
        assert!(issues[0].contains("expected `23` found `21`"));
        Ok(())
    }

    #[test]
    fn unknown_key_is_rejected() {
        let mut suppressed: Vec<usize> = Vec::new();
        let result: Result<Vec<MarkerSpan>> =
            parse_spans("a <!-- m:not_a_key -->0<!-- /m --> b\n", &mut suppressed);
        assert!(result.is_err());
    }

    #[test]
    fn marker_inside_fence_is_rejected() {
        let mut suppressed: Vec<usize> = Vec::new();
        let source: &str = "```\n<!-- m:dotnet_protectors -->23<!-- /m -->\n```\n";
        let result: Result<Vec<MarkerSpan>> = parse_spans(source, &mut suppressed);
        assert!(result.is_err());
    }

    #[test]
    fn unclosed_span_is_rejected() {
        let mut suppressed: Vec<usize> = Vec::new();
        let result: Result<Vec<MarkerSpan>> = parse_spans(
            "a <!-- m:dotnet_protectors -->23 and no close\n",
            &mut suppressed,
        );
        assert!(result.is_err());
    }
}
