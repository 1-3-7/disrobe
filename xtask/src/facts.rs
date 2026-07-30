use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use eyre::{Result, bail};
use serde::Deserialize;

use crate::fileio::read_text_bounded;

const MAX_RECOVERY_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const IGNORE_LOOKBACK_BYTES: usize = 256;
const VERIFIED_FLOOR: usize = 17;

#[derive(Debug, Deserialize)]
struct Recovery {
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize)]
struct Group {
    bars: Vec<Bar>,
}

#[derive(Debug, Deserialize)]
struct Bar {
    label: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    verified_by: Option<VerifiedBy>,
}

#[derive(Debug, Deserialize)]
struct VerifiedBy {
    path: String,
    function: String,
    #[serde(default)]
    conditional: Option<String>,
}

const SKIP_SHAPES: [(&str, &str); 5] = [
    ("return ;", "a bare early return"),
    ("return;", "a bare early return"),
    ("is_none() {", "an is_none guard"),
    ("is_err() {", "an is_err guard"),
    (".exists() {", "a path-existence guard"),
];

fn cited_function_region<'a>(text: &'a str, function: &str) -> Option<&'a str> {
    let needle: String = format!("fn {function}");
    let at: usize = text.find(&needle)?;
    let open: usize = at + text.get(at..)?.find('{')?;
    let body: &str = text.get(open..)?;

    let bytes: &[u8] = body.as_bytes();
    let mut depth: usize = 0;
    let mut index: usize = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'r' => {
                let mut hashes: usize = 0;
                let mut probe: usize = index + 1;
                while bytes.get(probe) == Some(&b'#') {
                    hashes += 1;
                    probe += 1;
                }
                if bytes.get(probe) == Some(&b'"') {
                    index = skip_raw_string(bytes, probe + 1, hashes);
                } else {
                    index += 1;
                }
            }
            b'"' => index = skip_quoted(bytes, index + 1, b'"'),
            b'\'' if is_char_literal(bytes, index) => {
                index = skip_quoted(bytes, index + 1, b'\'');
            }
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return body.get(..index);
                }
            }
            _ => index += 1,
        }
    }
    None
}

fn is_char_literal(bytes: &[u8], at: usize) -> bool {
    if bytes.get(at + 1) == Some(&b'\\') {
        return true;
    }
    bytes.get(at + 2) == Some(&b'\'')
}

fn skip_quoted(bytes: &[u8], from: usize, terminator: u8) -> usize {
    let mut index: usize = from;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == terminator => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

fn skip_raw_string(bytes: &[u8], from: usize, hashes: usize) -> usize {
    let mut index: usize = from;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let closed: bool = (1..=hashes).all(|off: usize| bytes.get(index + off) == Some(&b'#'));
            if closed {
                return index + hashes + 1;
            }
        }
        index += 1;
    }
    bytes.len()
}

fn skip_shapes_in(region: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for (pattern, description) in &SKIP_SHAPES {
        if region.contains(pattern) && !found.contains(description) {
            found.push(description);
        }
    }
    found
}

fn provenance_cites_documentation(source: &str) -> Option<String> {
    for token in source.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ';') {
        let trimmed: &str = token.trim_matches(|c: char| c == ',' || c == '`' || c == '"');
        let is_doc: bool = Path::new(trimmed).extension().is_some_and(|ext: &OsStr| {
            ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("mdx")
        });
        if is_doc {
            return Some(trimmed.to_owned());
        }
    }
    None
}

fn function_is_ignored(text: &str, at: usize) -> bool {
    let start: usize = at.saturating_sub(IGNORE_LOOKBACK_BYTES);
    let mut window_start: usize = start;
    while window_start < at && !text.is_char_boundary(window_start) {
        window_start += 1;
    }
    text.get(window_start..at)
        .is_some_and(|window: &str| window.contains("#[ignore"))
}

fn verify_citation(root: &Path, bar: &Bar, cited: &VerifiedBy, issues: &mut Vec<String>) {
    let label: &str = &bar.label;
    let rel: &str = &cited.path;

    if !rel.starts_with("crates/") {
        issues.push(format!(
            "bar `{label}` is verified by `{rel}`, which is not under crates/; a claim must be \
             checked by code the workspace builds, never by a document or a generated artifact"
        ));
        return;
    }
    if !(rel.contains("/src/") || rel.contains("/tests/")) {
        issues.push(format!(
            "bar `{label}` cites `{rel}`, which is neither a src nor a tests path"
        ));
        return;
    }

    let absolute: PathBuf = root.join(rel);
    if !absolute.is_file() {
        issues.push(format!(
            "bar `{label}` cites `{rel}`, which does not exist; a citation that points at a moved \
             or renamed file proves nothing and is exactly how a stale number survives"
        ));
        return;
    }

    let text: String = match read_text_bounded(&absolute, MAX_SOURCE_BYTES) {
        Ok(text) => text,
        Err(error) => {
            issues.push(format!(
                "bar `{label}` cites `{rel}`, which could not be read: {error}"
            ));
            return;
        }
    };

    let needle: String = format!("fn {}", cited.function);
    let Some(at): Option<usize> = text.find(&needle) else {
        issues.push(format!(
            "bar `{label}` cites `{}` in `{rel}`, but that function is not there; the test was \
             renamed or removed while the number stayed",
            cited.function
        ));
        return;
    };

    if function_is_ignored(&text, at) {
        issues.push(format!(
            "bar `{label}` is verified by `{}`, which is marked #[ignore]; a check that never runs \
             cannot fail",
            cited.function
        ));
    }

    if !text.contains(label) {
        issues.push(format!(
            "bar `{label}` cites `{}` in `{rel}`, but that file never names the bar it verifies, \
             so the citation is decorative and nothing ties the assertion to this claim",
            cited.function
        ));
    }

    let Some(region): Option<&str> = cited_function_region(&text, &cited.function) else {
        issues.push(format!(
            "bar `{label}` cites `{}` in `{rel}`, but its body could not be delimited, so this gate \
             cannot tell whether the check runs; treat that as a failure rather than a pass",
            cited.function
        ));
        return;
    };

    let shapes: Vec<&'static str> = skip_shapes_in(region);
    if !shapes.is_empty() && cited.conditional.is_none() {
        issues.push(format!(
            "bar `{label}` is verified by `{}`, whose body carries {}. A citation shaped like that \
             can grade nothing, or grade a smaller population than the published figure describes, \
             and still report success, so counting it as proof overstates what is checked. Either \
             make the absent input fatal the way enforce_fixture_requirement already does, or state \
             why enforcement is conditional in a `conditional` field on this bar's verified_by so \
             the weakness is declared and countable instead of invisible",
            cited.function,
            shapes.join(" and ")
        ));
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let raw: String = read_text_bounded(&path, MAX_RECOVERY_JSON_BYTES)?;
    let recovery: Recovery = serde_json::from_str(&raw)?;

    let mut issues: Vec<String> = Vec::new();
    let mut verified: usize = 0;
    let mut conditional: usize = 0;
    let mut total: usize = 0;

    for group in &recovery.groups {
        for bar in &group.bars {
            total += 1;
            if let Some(source) = bar.source.as_deref()
                && let Some(cited) = provenance_cites_documentation(source)
            {
                issues.push(format!(
                    "bar `{}` records its provenance as `{cited}`, a document this gate also \
                     validates against this same file; that is a copy checked against its own \
                     original and it can never fail. Cite the code instead.",
                    bar.label
                ));
            }
            if let Some(cited) = bar.verified_by.as_ref() {
                verified += 1;
                if cited.conditional.is_some() {
                    conditional += 1;
                }
                verify_citation(root, bar, cited, &mut issues);
            }
        }
    }

    if verified < VERIFIED_FLOOR {
        issues.push(format!(
            "only {verified} of {total} published bar(s) name a test that asserts them against the \
             code (floor {VERIFIED_FLOOR}); this floor only ever rises"
        ));
    }

    if issues.is_empty() {
        let unconditional: usize = verified.saturating_sub(conditional);
        println!(
            "xtask regen: claim-provenance cross-check ok ({verified} of {total} bar(s) name a test \
             that exists, is not #[ignore]d and names the bar it verifies; {unconditional} of those \
             enforce unconditionally and {conditional} declare enforcement conditional on an input \
             this gate cannot guarantee is present, and no bar cites a document as its own source)"
        );
        Ok(())
    } else {
        bail!(
            "xtask regen: {} claim(s) in xtask/data/recovery.json are not sourced from code:\n  {}",
            issues.len(),
            issues.join("\n  ")
        )
    }
}
