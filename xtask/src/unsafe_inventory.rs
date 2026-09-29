use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::doc_region::{self, Mode, RegionSyntax};
use crate::fileio::read_text_bounded;

const SYNTAX: RegionSyntax = RegionSyntax {
    open_prefix: "<!-- unsafe:",
    close: "<!-- /unsafe -->",
};
const SITES_SLUG: &str = "sites";
const DOC: &str = "SECURITY.md";
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MACRO_EXPANSION_CRATES: [&str; 1] = ["disrobe-python"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrateLint {
    Forbid,
    Deny,
    Unset,
}

#[derive(Debug)]
struct CrateReport {
    lint: CrateLint,
    expected_sites: usize,
    allowed_sites: Vec<String>,
    unsafe_tokens: usize,
}

pub(crate) fn run(root: &Path, mode: Mode) -> Result<()> {
    let reports: BTreeMap<String, CrateReport> = survey(root)?;
    let issues: Vec<String> = coherence_issues(&reports);
    if !issues.is_empty() {
        bail!(
            "xtask unsafe-inventory: {} crate(s) break the unsafe policy:\n  {}",
            issues.len(),
            issues.join("\n  ")
        );
    }
    let rendered: String = render(&reports);
    let path: PathBuf = root.join(DOC);
    let text: String = doc_region::read_doc(&path)?;
    let updated: String = doc_region::rewrite(SYNTAX, &text, &|slug: &str| {
        if slug == SITES_SLUG {
            Ok(rendered.clone())
        } else {
            bail!("unknown unsafe inventory region `{slug}`")
        }
    })?;
    if !text.contains(&format!("{}{SITES_SLUG} -->", SYNTAX.open_prefix)) {
        bail!("{DOC} carries no `<!-- unsafe:{SITES_SLUG} -->` region for the unsafe inventory");
    }
    match mode {
        Mode::Write => {
            if updated != text {
                std::fs::write(&path, &updated)
                    .wrap_err_with(|| format!("writing {}", path.display()))?;
            }
        }
        Mode::Check => {
            if updated != text {
                bail!(
                    "{DOC}'s unsafe inventory is stale; it should read: {rendered}; run `cargo run \
                     -p xtask -- regen`"
                );
            }
        }
    }
    println!(
        "xtask unsafe-inventory: {} crate(s) forbid unsafe code; the rest deny it and allow it \
         only at the listed `#[expect(unsafe_code, reason = ..)]` sites: {rendered}",
        reports
            .values()
            .filter(|r: &&CrateReport| r.lint == CrateLint::Forbid)
            .count()
    );
    Ok(())
}

fn survey(root: &Path) -> Result<BTreeMap<String, CrateReport>> {
    let crates_dir: PathBuf = root.join("crates");
    let mut out: BTreeMap<String, CrateReport> = BTreeMap::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&crates_dir)
        .wrap_err_with(|| format!("listing {}", crates_dir.display()))?
        .filter_map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry.ok().map(|e: std::fs::DirEntry| e.path())
        })
        .filter(|path: &PathBuf| path.is_dir())
        .collect();
    entries.sort();
    for dir in entries {
        let roots: Vec<PathBuf> = ["src/lib.rs", "src/main.rs"]
            .iter()
            .map(|rel: &&str| dir.join(rel))
            .filter(|path: &PathBuf| path.is_file())
            .collect();
        if roots.is_empty() {
            continue;
        }
        let name: String = dir
            .file_name()
            .map(|n: &std::ffi::OsStr| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut lint: CrateLint = CrateLint::Unset;
        for crate_root in &roots {
            let text: String = read_text_bounded(crate_root, MAX_SOURCE_BYTES)?;
            let this: CrateLint = crate_lint(&text);
            lint = match (lint, this) {
                (CrateLint::Unset, found) | (found, CrateLint::Unset) => found,
                (CrateLint::Deny, _) | (_, CrateLint::Deny) => CrateLint::Deny,
                (CrateLint::Forbid, CrateLint::Forbid) => CrateLint::Forbid,
            };
        }
        let mut report: CrateReport = CrateReport {
            lint,
            expected_sites: 0,
            allowed_sites: Vec::new(),
            unsafe_tokens: 0,
        };
        for file in production_sources(&dir.join("src"))? {
            let text: String = read_text_bounded(&file, MAX_SOURCE_BYTES)?;
            let code: String = strip_comments_and_strings(&text);
            report.unsafe_tokens += count_unsafe_tokens(&code);
            for attribute in attributes(&text, "#[expect(") {
                if mentions_unsafe_code(attribute) {
                    report.expected_sites += 1;
                }
            }
            for attribute in attributes(&text, "#[allow(") {
                if mentions_unsafe_code(attribute) {
                    report.allowed_sites.push(doc_region::label(root, &file));
                }
            }
        }
        out.insert(name, report);
    }
    Ok(out)
}

fn production_sources(src: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(src) {
        let entry: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", src.display()))?;
        let path: &Path = entry.path();
        let test_only: bool = path
            .file_name()
            .is_some_and(|n: &std::ffi::OsStr| n == "tests.rs")
            || path.strip_prefix(src).is_ok_and(|rel: &Path| {
                rel.components()
                    .any(|c: std::path::Component<'_>| c.as_os_str() == "tests")
            });
        if path.is_file()
            && path
                .extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext == "rs")
            && !test_only
        {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn crate_lint(text: &str) -> CrateLint {
    let code: String = strip_comments_and_strings(text);
    if code.contains("#![forbid(unsafe_code)]") {
        CrateLint::Forbid
    } else if code.contains("#![deny(unsafe_code)]") {
        CrateLint::Deny
    } else {
        CrateLint::Unset
    }
}

fn attributes<'a>(text: &'a str, opening: &str) -> Vec<&'a str> {
    let mut found: Vec<&'a str> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = text.get(from..).and_then(|rest: &str| rest.find(opening)) {
        let start: usize = from + rel;
        let body_start: usize = start + opening.len();
        let end: usize = attribute_end(text.as_bytes(), body_start).unwrap_or(text.len());
        found.push(text.get(start..end).unwrap_or_default());
        from = end.max(body_start);
    }
    found
}

fn attribute_end(bytes: &[u8], mut at: usize) -> Option<usize> {
    let mut depth: usize = 1;
    let mut in_string: bool = false;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' if in_string => at += 1,
            b'"' => in_string = !in_string,
            b'(' if !in_string => depth += 1,
            b')' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(at + 1);
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

fn mentions_unsafe_code(attribute: &str) -> bool {
    let code: String = strip_comments_and_strings(attribute);
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word: &str| word == "unsafe_code")
}

fn count_unsafe_tokens(code: &str) -> usize {
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word: &&str| *word == "unsafe")
        .count()
}

fn strip_comments_and_strings(text: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                i += 2;
            }
            b'\'' if bytes.get(i + 1) == Some(&b'\\') && bytes.get(i + 3) == Some(&b'\'') => {
                i += 4;
            }
            b'\'' if bytes.get(i + 2) == Some(&b'\'') => {
                i += 3;
            }
            b'"' => {
                out.push(b'"');
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                out.push(b'"');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn coherence_issues(reports: &BTreeMap<String, CrateReport>) -> Vec<String> {
    let mut issues: Vec<String> = Vec::new();
    for (name, report) in reports {
        for site in &report.allowed_sites {
            issues.push(format!(
                "{name}: {site} allows `unsafe_code`; state why with `#[expect(unsafe_code, \
                 reason = ..)]` on the item instead"
            ));
        }
        let macro_crate: bool = MACRO_EXPANSION_CRATES.contains(&name.as_str());
        match report.lint {
            CrateLint::Forbid if report.expected_sites > 0 => issues.push(format!(
                "{name} forbids unsafe code yet carries {} `#[expect(unsafe_code)]` site(s)",
                report.expected_sites
            )),
            CrateLint::Deny if report.expected_sites == 0 => issues.push(format!(
                "{name} denies unsafe code but no item expects it; raise the lint to \
                 `#![forbid(unsafe_code)]`"
            )),
            CrateLint::Unset if !macro_crate => issues.push(format!(
                "{name} sets neither `#![forbid(unsafe_code)]` nor `#![deny(unsafe_code)]`"
            )),
            CrateLint::Unset if report.unsafe_tokens > 0 => issues.push(format!(
                "{name} leaves the lint off for its binding macros but writes `unsafe` \
                 {} time(s) in its own source",
                report.unsafe_tokens
            )),
            _ => {}
        }
    }
    issues
}

fn render(reports: &BTreeMap<String, CrateReport>) -> String {
    reports
        .iter()
        .filter(|(_, report): &(&String, &CrateReport)| report.expected_sites > 0)
        .map(|(name, report): (&String, &CrateReport)| {
            format!("`{name}` {}", report.expected_sites)
        })
        .collect::<Vec<String>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_multi_line_expect_with_a_parenthesised_reason_is_one_site() {
        let text: &str = "#[expect(\n    unsafe_code,\n    reason = \"a (b) c\"\n)]\nfn f() {}\n";
        let found: Vec<&str> = attributes(text, "#[expect(");
        assert_eq!(found.len(), 1);
        assert!(mentions_unsafe_code(found[0]));
    }

    #[test]
    fn unsafe_code_named_only_inside_a_reason_string_is_not_a_site() {
        let text: &str =
            "#[expect(clippy::cast_possible_truncation, reason = \"not unsafe_code\")]\n";
        let found: Vec<&str> = attributes(text, "#[expect(");
        assert_eq!(found.len(), 1);
        assert!(!mentions_unsafe_code(found[0]));
    }

    #[test]
    fn unsafe_in_comments_and_strings_is_not_counted() {
        let code: String =
            strip_comments_and_strings("// unsafe here\nlet s = \"unsafe\";\nunsafe { x() }\n");
        assert_eq!(count_unsafe_tokens(&code), 1);
    }

    #[test]
    fn a_deny_crate_without_sites_and_an_allow_are_both_reported() {
        let mut reports: BTreeMap<String, CrateReport> = BTreeMap::new();
        reports.insert(
            "disrobe-a".to_owned(),
            CrateReport {
                lint: CrateLint::Deny,
                expected_sites: 0,
                allowed_sites: vec!["crates/disrobe-a/src/x.rs".to_owned()],
                unsafe_tokens: 1,
            },
        );
        reports.insert(
            "disrobe-b".to_owned(),
            CrateReport {
                lint: CrateLint::Unset,
                expected_sites: 0,
                allowed_sites: Vec::new(),
                unsafe_tokens: 0,
            },
        );
        let issues: Vec<String> = coherence_issues(&reports);
        assert_eq!(issues.len(), 3, "{issues:?}");
    }

    #[test]
    fn the_rendered_inventory_lists_only_crates_with_sites_in_name_order() {
        let mut reports: BTreeMap<String, CrateReport> = BTreeMap::new();
        for (name, sites) in [("disrobe-z", 2), ("disrobe-a", 1), ("disrobe-m", 0)] {
            reports.insert(
                name.to_owned(),
                CrateReport {
                    lint: if sites > 0 {
                        CrateLint::Deny
                    } else {
                        CrateLint::Forbid
                    },
                    expected_sites: sites,
                    allowed_sites: Vec::new(),
                    unsafe_tokens: sites,
                },
            );
        }
        assert_eq!(render(&reports), "`disrobe-a` 1, `disrobe-z` 2");
    }
}
