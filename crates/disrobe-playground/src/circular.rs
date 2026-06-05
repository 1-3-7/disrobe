use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CircularityKind {
    SelfEmittedGolden,
    SyntheticSelfReference,
    ProvenanceSelfReference,
    PassOutputEqualsOwnGolden,
}

impl CircularityKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SelfEmittedGolden => "self-emitted-golden",
            Self::SyntheticSelfReference => "synthetic-self-reference",
            Self::ProvenanceSelfReference => "provenance-self-reference",
            Self::PassOutputEqualsOwnGolden => "pass-output-equals-own-golden",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircularityFinding {
    pub kind: CircularityKind,
    pub path: String,
    pub pass_id: Option<String>,
    pub evidence: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircularityReport {
    pub findings: Vec<CircularityFinding>,
    pub files_scanned: usize,
}

impl CircularityReport {
    #[must_use]
    pub const fn count(&self) -> usize {
        self.findings.len()
    }

    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    #[must_use]
    pub fn findings_for(&self, kind: CircularityKind) -> Vec<&CircularityFinding> {
        self.findings
            .iter()
            .filter(|f: &&CircularityFinding| f.kind == kind)
            .collect()
    }
}

const CIRCULAR_MARKER: &str = "disrobe-playground:circular-oracle";
const SELF_EMIT_MARKER: &str = "golden-emitted-by-pass-under-test";

#[must_use]
pub fn scan_circularity(roots: &[PathBuf]) -> CircularityReport {
    let mut findings: Vec<CircularityFinding> = Vec::new();
    let mut files_scanned: usize = 0;
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(core::result::Result::ok)
        {
            let path: &Path = entry.path();
            if !path.is_file() {
                continue;
            }
            if !is_scannable(path) {
                continue;
            }
            files_scanned += 1;
            scan_file(root, path, &mut findings);
        }
    }
    findings.sort_by(|a: &CircularityFinding, b: &CircularityFinding| {
        (a.kind, &a.path).cmp(&(b.kind, &b.path))
    });
    findings.dedup();
    CircularityReport {
        findings,
        files_scanned,
    }
}

fn is_scannable(path: &Path) -> bool {
    let ext_ok: bool = path
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        .is_some_and(|e: &str| matches!(e, "json" | "toml" | "txt" | "rs" | "md"));
    let name_marker: bool = path
        .file_name()
        .and_then(|n: &std::ffi::OsStr| n.to_str())
        .is_some_and(|n: &str| {
            let lower: String = n.to_ascii_lowercase();
            lower.contains("golden") || lower.contains("oracle") || lower.contains("canary")
        });
    let parent_marker: bool = path.components().any(|c: std::path::Component<'_>| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s: &str| s == "goldens" || s.ends_with("_circular_canary"))
    });
    ext_ok && (name_marker || parent_marker || is_golden_dir_member(path))
}

fn is_golden_dir_member(path: &Path) -> bool {
    path.to_string_lossy()
        .replace('\\', "/")
        .contains("/goldens/")
}

fn scan_file(root: &Path, path: &Path, findings: &mut Vec<CircularityFinding>) {
    let Ok(text): Result<String, std::io::Error> = std::fs::read_to_string(path) else {
        return;
    };
    let rel: String = display_rel(root, path);
    let lower_path: String = rel.to_ascii_lowercase();

    if (lower_path.contains("synth_") || lower_path.contains("synthetic_"))
        && lower_path.contains("oracle")
    {
        findings.push(CircularityFinding {
            kind: CircularityKind::SyntheticSelfReference,
            path: rel.clone(),
            pass_id: None,
            evidence: "oracle artifact lives under a synth_/synthetic_ path".to_owned(),
        });
    }

    if let Some(pass_id) = explicit_circular_marker(&text) {
        findings.push(CircularityFinding {
            kind: CircularityKind::PassOutputEqualsOwnGolden,
            path: rel.clone(),
            pass_id: Some(pass_id.clone()),
            evidence: format!(
                "explicit {CIRCULAR_MARKER} declaration: golden asserted equal to output of pass `{pass_id}`",
            ),
        });
    }

    if let Some(pass_id) = self_emit_provenance(&text) {
        findings.push(CircularityFinding {
            kind: CircularityKind::SelfEmittedGolden,
            path: rel.clone(),
            pass_id: Some(pass_id.clone()),
            evidence: format!(
                "{SELF_EMIT_MARKER}: golden provenance header names emitting pass `{pass_id}` as its own oracle",
            ),
        });
    }

    if let Some(evidence) = provenance_self_reference(&text) {
        findings.push(CircularityFinding {
            kind: CircularityKind::ProvenanceSelfReference,
            path: rel,
            pass_id: None,
            evidence,
        });
    }
}

fn explicit_circular_marker(text: &str) -> Option<String> {
    let idx: usize = text.find(CIRCULAR_MARKER)?;
    let tail: &str = &text[idx + CIRCULAR_MARKER.len()..];
    let pass: String = tail
        .chars()
        .skip_while(|c: &char| !c.is_ascii_alphanumeric())
        .take_while(|c: &char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if pass.is_empty() {
        Some("<unspecified>".to_owned())
    } else {
        Some(pass)
    }
}

fn self_emit_provenance(text: &str) -> Option<String> {
    let idx: usize = text.find(SELF_EMIT_MARKER)?;
    let tail: &str = &text[idx + SELF_EMIT_MARKER.len()..];
    let pass: String = tail
        .chars()
        .skip_while(|c: &char| !c.is_ascii_alphanumeric())
        .take_while(|c: &char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if pass.is_empty() {
        Some("<unspecified>".to_owned())
    } else {
        Some(pass)
    }
}

fn provenance_self_reference(text: &str) -> Option<String> {
    let lower: String = text.to_ascii_lowercase();
    let needle: &str = "expected_emitted_by";
    let idx: usize = lower.find(needle)?;
    let segment: &str = &lower[idx..(idx + 200).min(lower.len())];
    if segment.contains("pass_under_test") || segment.contains("same_pass") {
        return Some(format!(
            "provenance declares the expected artifact was emitted by the pass under test ({})",
            segment.lines().next().unwrap_or("").trim()
        ));
    }
    None
}

fn display_rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
