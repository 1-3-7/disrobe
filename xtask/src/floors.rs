use std::path::{Path, PathBuf};

use eyre::{Result, bail};

use crate::fileio::read_text_bounded;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DOC_BYTES: u64 = 4 * 1024 * 1024;

struct FloorClaim {
    constant: &'static str,
    source: &'static str,
    sites: &'static [(&'static str, &'static str)],
}

const DALVIK_VERIFIER_GATE: &str = "crates/disrobe-pass-jvm/tests/dalvik_verifier_gate.rs";

const CLAIMS: [FloorClaim; 6] = [
    FloorClaim {
        constant: "OBJECT_PCT_FLOOR",
        source: "crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs",
        sites: &[
            ("README.md", "floor {}% `[CI]`"),
            (
                "docs/src/languages/python.md",
                "above a {}% floor a committed CI gate enforces",
            ),
            ("docs/src/python-bindings.md", "CI floor {}%"),
            (
                "docs/src/architecture/whitepaper.md",
                "holds the per-object rate above a floor of {}%",
            ),
        ],
    },
    FloorClaim {
        constant: "PER_METHOD_JAVAC_OK_FLOOR",
        source: "crates/disrobe-pass-jvm/tests/decompile_recompile_rate.rs",
        sites: &[(
            "docs/src/architecture/whitepaper.md",
            "sets `PER_METHOD_JAVAC_OK_FLOOR = {}`",
        )],
    },
    FloorClaim {
        constant: "IL_EQUIVALENCE_FLOOR",
        source: "crates/disrobe-pass-dotnet/tests/whole_type_il_equivalence_oracle.rs",
        sites: &[(
            "docs/src/architecture/whitepaper.md",
            "sets `IL_EQUIVALENCE_FLOOR = {}`",
        )],
    },
    FloorClaim {
        constant: "REEXEC_FLOOR_NUM",
        source: "crates/disrobe-pass-lua/tests/reexec_diff_oracle.rs",
        sites: &[(
            "docs/src/architecture/whitepaper.md",
            "sets `REEXEC_FLOOR_NUM = {}`",
        )],
    },
    FloorClaim {
        constant: "VERIFY_CLEAN_CLASS_FLOOR",
        source: DALVIK_VERIFIER_GATE,
        sites: &[("README.md", "{} / {} presentable classes clean")],
    },
    FloorClaim {
        constant: "BODY_VERIFY_CLEAN_FLOOR",
        source: DALVIK_VERIFIER_GATE,
        sites: &[
            ("README.md", "{} re-hosted bodies clean"),
            (
                "docs/src/languages/jvm-android.md",
                "{} re-hosted bodies verify clean",
            ),
        ],
    },
];

fn literal_after_equals(line: &str) -> Option<&str> {
    let after: &str = line.split_once('=')?.1;
    let trimmed: &str = after.trim();
    let end: usize = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(trimmed.len());
    let literal: &str = trimmed.get(..end)?;
    if literal.is_empty() {
        None
    } else {
        Some(literal)
    }
}

fn declared_value(text: &str, constant: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed: &str = line.trim();
        if !trimmed.starts_with("const ") {
            continue;
        }
        if !trimmed.contains(constant) {
            continue;
        }
        if let Some(literal) = literal_after_equals(trimmed) {
            return Some(literal.trim_end_matches('.').to_owned());
        }
    }
    None
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut issues: Vec<String> = Vec::new();
    let mut checked: usize = 0;

    for claim in &CLAIMS {
        let source_path: PathBuf = root.join(claim.source);
        let source_text: String = match read_text_bounded(&source_path, MAX_SOURCE_BYTES) {
            Ok(text) => text,
            Err(error) => {
                issues.push(format!(
                    "the gate that owns `{}` is missing at `{}`: {error}",
                    claim.constant, claim.source
                ));
                continue;
            }
        };

        let Some(value): Option<String> = declared_value(&source_text, claim.constant) else {
            issues.push(format!(
                "`{}` is no longer declared in `{}`, so every document that publishes it is \
                 unchecked",
                claim.constant, claim.source
            ));
            continue;
        };

        for (doc, template) in claim.sites {
            let doc_path: PathBuf = root.join(doc);
            let doc_text: String = match read_text_bounded(&doc_path, MAX_DOC_BYTES) {
                Ok(text) => text,
                Err(error) => {
                    issues.push(format!("{doc} could not be read: {error}"));
                    continue;
                }
            };
            let expected: String = template.replace("{}", &value);
            checked += 1;
            if !doc_text.contains(&expected) {
                issues.push(format!(
                    "{doc} does not state the floor as `{expected}`, but `{}` in {} is {value}; a \
                     document publishing a floor other than the one the gate enforces understates \
                     or overstates what is actually guaranteed",
                    claim.constant, claim.source
                ));
            }
        }
    }

    if issues.is_empty() {
        println!(
            "xtask regen: published-floor cross-check ok ({checked} document site(s) state the \
             same floor their gate enforces)"
        );
        Ok(())
    } else {
        bail!(
            "xtask regen: {} published floor(s) disagree with the constant the gate enforces:\n  {}",
            issues.len(),
            issues.join("\n  ")
        )
    }
}
