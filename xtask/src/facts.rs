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
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let raw: String = read_text_bounded(&path, MAX_RECOVERY_JSON_BYTES)?;
    let recovery: Recovery = serde_json::from_str(&raw)?;

    let mut issues: Vec<String> = Vec::new();
    let mut verified: usize = 0;
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
        println!(
            "xtask regen: claim-provenance cross-check ok ({verified} of {total} bar(s) are \
             asserted against code by a named test that exists and runs, and no bar cites a \
             document as its own source)"
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
