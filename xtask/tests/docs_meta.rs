#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unwrap_in_result,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .expect("xtask manifest dir has a parent")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e: std::io::Error| {
        panic!("reading {}: {e}", path.display());
    })
}

fn assert_lf_only(path: &Path) {
    let bytes: Vec<u8> = fs::read(path).unwrap_or_else(|e: std::io::Error| {
        panic!("reading bytes of {}: {e}", path.display());
    });
    assert!(
        !bytes.contains(&b'\r'),
        "{} contains a CR byte; line endings must be LF-only",
        path.display()
    );
}

#[test]
fn threat_model_exists_and_is_linked() {
    let root: PathBuf = workspace_root();
    let threat: PathBuf = root.join("docs").join("src").join("threat-model.md");
    assert!(threat.is_file(), "missing {}", threat.display());
    assert_lf_only(&threat);

    let body: String = read(&threat);
    assert!(
        body.contains("# Threat model"),
        "threat-model.md missing its title heading"
    );
    for needle in ["trust boundar", "untrusted", "Supply chain", ".dr envelope"] {
        assert!(
            body.contains(needle),
            "threat-model.md missing expected content `{needle}`"
        );
    }

    let summary: String = read(&root.join("docs").join("src").join("SUMMARY.md"));
    assert!(
        summary.contains("threat-model.md"),
        "SUMMARY.md does not list threat-model.md"
    );

    let readme: String = read(&root.join("README.md"));
    assert!(
        readme.to_ascii_lowercase().contains("threat-model"),
        "README.md does not contain a threat-model link"
    );
}

#[test]
fn pyarmor_stance_exists_with_legal_headings() {
    let root: PathBuf = workspace_root();
    let stance: PathBuf = root.join("docs").join("legal").join("pyarmor-stance.md");
    assert!(stance.is_file(), "missing {}", stance.display());
    assert_lf_only(&stance);

    let body: String = read(&stance);
    for needle in [
        "1201(f)",
        "Software Directive",
        "Art. 6",
        "AMBER",
        "--i-have-authorization",
        "EULA",
    ] {
        assert!(
            body.contains(needle),
            "pyarmor-stance.md missing expected legal anchor `{needle}`"
        );
    }
}

#[test]
fn adr_set_is_exactly_five_madr_documents() {
    let root: PathBuf = workspace_root();
    let decisions: PathBuf = root.join("docs").join("decisions");
    assert!(decisions.is_dir(), "missing {}", decisions.display());

    let mut adrs: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&decisions).expect("reading docs/decisions") {
        let path: PathBuf = entry.expect("dir entry").path();
        let name: String = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        let is_adr: bool = name.ends_with(".md")
            && name
                .split('-')
                .next()
                .is_some_and(|p: &str| p.len() == 4 && p.chars().all(|c: char| c.is_ascii_digit()));
        if is_adr {
            adrs.push(path);
        }
    }
    adrs.sort();
    assert_eq!(
        adrs.len(),
        5,
        "expected exactly 5 NNNN-*.md ADRs, found {}: {adrs:?}",
        adrs.len()
    );

    for adr in &adrs {
        assert_lf_only(adr);
        let body: String = read(adr);
        assert!(
            body.contains("## Decision"),
            "{} missing a `## Decision` heading",
            adr.display()
        );
        assert!(
            body.contains("## Context"),
            "{} missing a `## Context` heading",
            adr.display()
        );
        assert!(
            body.contains("## Consequences"),
            "{} missing a `## Consequences` heading",
            adr.display()
        );
    }
}

fn registry_codes(root: &Path) -> BTreeSet<String> {
    let dir: PathBuf = root
        .join("crates")
        .join("disrobe-cli")
        .join("src")
        .join("cli")
        .join("explain")
        .join("codes");
    let mut codes: BTreeSet<String> = BTreeSet::new();
    for entry in fs::read_dir(&dir).expect("reading explain/codes") {
        let path: PathBuf = entry.expect("dir entry").path();
        let name: String = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if !name.ends_with(".rs") || name == "mod.rs" {
            continue;
        }
        let text: String = read(&path);
        for raw in text.lines() {
            let line: &str = raw.trim();
            let Some(rest): Option<&str> = line.strip_prefix("code:") else {
                continue;
            };
            let Some(open): Option<usize> = rest.find('"') else {
                continue;
            };
            let after: &str = &rest[open + 1..];
            let Some(close): Option<usize> = after.find('"') else {
                continue;
            };
            let code: &str = &after[..close];
            if code.starts_with("DR-") && code.matches('-').count() == 2 {
                codes.insert(code.to_owned());
            }
        }
    }
    codes
}

#[test]
fn every_emittable_error_code_has_a_doc() {
    let root: PathBuf = workspace_root();
    let codes: BTreeSet<String> = registry_codes(&root);
    assert!(
        codes.len() >= 100,
        "registry parse found only {} codes; parser likely broke",
        codes.len()
    );

    let errors_dir: PathBuf = root.join("docs").join("errors");
    assert!(errors_dir.is_dir(), "missing {}", errors_dir.display());

    let mut missing: Vec<String> = Vec::new();
    for code in &codes {
        let doc: PathBuf = errors_dir.join(format!("{code}.md"));
        if doc.is_file() {
            assert_lf_only(&doc);
            let body: String = read(&doc);
            assert!(
                body.contains(code.as_str()),
                "{} does not name its own code",
                doc.display()
            );
        } else {
            missing.push(code.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "missing docs/errors/<code>.md for: {missing:?} -- run `cargo run -p xtask -- gen-error-docs`"
    );

    let index: PathBuf = errors_dir.join("README.md");
    assert!(
        index.is_file(),
        "missing error-code index {}",
        index.display()
    );
    assert_lf_only(&index);
}
