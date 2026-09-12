#![cfg(feature = "chain")]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_core::chain::{ChainDocument, NodeDoc, NodeId};
use serde::Serialize;

use super::output::{OutputFormat, emit};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Difference {
    scope: String,
    field: &'static str,
    left: String,
    right: String,
}

#[derive(Debug, Clone, Serialize)]
struct DiffReport {
    left: String,
    right: String,
    identical: bool,
    differences: Vec<Difference>,
}

#[derive(Debug, Clone, Serialize)]
struct GuardReport {
    subject: String,
    reference: String,
    ok: bool,
    violations: Vec<Difference>,
}

fn load(path: &Path) -> miette::Result<ChainDocument> {
    let bytes: Vec<u8> = std::fs::read(path).map_err(|e| {
        miette::miette!(
            "DR-CLI-0310: cannot read chain.json {}: {e}",
            path.display()
        )
    })?;
    serde_json::from_slice::<ChainDocument>(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0311: {} is not a valid disrobe.chain/v1 document: {e}",
            path.display()
        )
    })
}

fn index_nodes(doc: &ChainDocument) -> BTreeMap<NodeId, &NodeDoc> {
    doc.nodes.iter().map(|n: &NodeDoc| (n.id, n)).collect()
}

fn pass_label(node: &NodeDoc) -> String {
    node.pass.clone().unwrap_or_else(|| "(input)".to_string())
}

fn compare(left: &ChainDocument, right: &ChainDocument) -> Vec<Difference> {
    let mut diffs: Vec<Difference> = Vec::new();
    if left.verdict != right.verdict {
        diffs.push(Difference {
            scope: "document".to_string(),
            field: "verdict",
            left: format!("{:?}", left.verdict),
            right: format!("{:?}", right.verdict),
        });
    }
    if left.final_format != right.final_format {
        diffs.push(Difference {
            scope: "document".to_string(),
            field: "final-format",
            left: format!("{:?}", left.final_format),
            right: format!("{:?}", right.final_format),
        });
    }
    let left_index: BTreeMap<NodeId, &NodeDoc> = index_nodes(left);
    let right_index: BTreeMap<NodeId, &NodeDoc> = index_nodes(right);
    let mut ids: Vec<NodeId> = left_index
        .keys()
        .chain(right_index.keys())
        .copied()
        .collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let scope: String = format!("node {id}");
        match (left_index.get(&id), right_index.get(&id)) {
            (Some(l), None) => diffs.push(Difference {
                scope,
                field: "presence",
                left: pass_label(l),
                right: "(absent)".to_string(),
            }),
            (None, Some(r)) => diffs.push(Difference {
                scope,
                field: "presence",
                left: "(absent)".to_string(),
                right: pass_label(r),
            }),
            (Some(l), Some(r)) => {
                if l.pass != r.pass {
                    diffs.push(Difference {
                        scope: scope.clone(),
                        field: "pass",
                        left: pass_label(l),
                        right: pass_label(r),
                    });
                }
                if l.output_blake3 != r.output_blake3 {
                    diffs.push(Difference {
                        scope: scope.clone(),
                        field: "output-blake3",
                        left: l
                            .output_blake3
                            .clone()
                            .unwrap_or_else(|| "(none)".to_string()),
                        right: r
                            .output_blake3
                            .clone()
                            .unwrap_or_else(|| "(none)".to_string()),
                    });
                }
                if l.output_size != r.output_size {
                    diffs.push(Difference {
                        scope: scope.clone(),
                        field: "output-size",
                        left: format!("{:?}", l.output_size),
                        right: format!("{:?}", r.output_size),
                    });
                }
                if l.verdict != r.verdict {
                    diffs.push(Difference {
                        scope,
                        field: "verdict",
                        left: format!("{:?}", l.verdict),
                        right: format!("{:?}", r.verdict),
                    });
                }
            }
            (None, None) => {}
        }
    }
    diffs
}

pub(crate) fn run_diff(
    left_path: PathBuf,
    right_path: PathBuf,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let left: ChainDocument = load(&left_path)?;
    let right: ChainDocument = load(&right_path)?;
    let differences: Vec<Difference> = compare(&left, &right);
    let identical: bool = differences.is_empty();
    let report: DiffReport = DiffReport {
        left: left_path.display().to_string(),
        right: right_path.display().to_string(),
        identical,
        differences,
    };
    emit(fmt, &report, || {
        if report.identical {
            println!("chain documents are structurally identical");
        } else {
            println!("{} difference(s):", report.differences.len());
            for diff in &report.differences {
                println!(
                    "  {} [{}]: {} != {}",
                    diff.scope, diff.field, diff.left, diff.right
                );
            }
        }
    })
}

pub(crate) fn run_guard(
    subject_path: PathBuf,
    reference_path: PathBuf,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let subject: ChainDocument = load(&subject_path)?;
    let reference: ChainDocument = load(&reference_path)?;
    let violations: Vec<Difference> = compare(&reference, &subject)
        .into_iter()
        .filter(|d: &Difference| matches!(d.field, "output-blake3" | "presence"))
        .collect();
    let ok: bool = violations.is_empty();
    let report: GuardReport = GuardReport {
        subject: subject_path.display().to_string(),
        reference: reference_path.display().to_string(),
        ok,
        violations,
    };
    emit(fmt, &report, || {
        if report.ok {
            println!(
                "guard ok: every stage output in {} matches the reference",
                report.subject
            );
        } else {
            println!(
                "guard FAILED: {} stage integrity violation(s):",
                report.violations.len()
            );
            for violation in &report.violations {
                println!(
                    "  {} [{}]: reference {} != subject {}",
                    violation.scope, violation.field, violation.left, violation.right
                );
            }
        }
    })?;
    if report.ok {
        Ok(())
    } else {
        Err(miette::miette!(
            "DR-CLI-0313: guard failed: {} stage integrity violation(s) vs reference",
            report.violations.len()
        ))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const DOC_A: &str = r#"{
      "schema": "disrobe.chain/v1",
      "tool_version": "0.10.0",
      "input": { "path": "a.bin", "blake3": "aa", "size": 4, "detected": [] },
      "spec": { "raw": "auto:8", "kind": "auto", "cap": 8 },
      "topology": "linear",
      "root_node_id": 0,
      "nodes": [
        { "id": 0, "parent_id": null, "depth": 0, "branch_id": "root",
          "pass": "pyarmor.unpack", "format_tag_in": "pyarmor",
          "input_blake3": "aa", "input_size": 4,
          "output_kind": null, "output_blake3": "bb", "output_size": 8,
          "duration_ms": 1, "detector_picks": [], "artifacts": [],
          "metadata": {}, "verdict": "ok", "error": null }
      ],
      "verdict": "complete",
      "final_format": "py-source",
      "stats": { "layers": 1, "branches": 1, "total_ms": 1,
        "max_branch_depth": 0, "detector_calls": 1, "rejected_passes": 0 }
    }"#;

    fn doc_from(json: &str) -> ChainDocument {
        serde_json::from_str::<ChainDocument>(json).expect("valid fixture doc")
    }

    #[test]
    fn identical_documents_have_no_differences() {
        let a: ChainDocument = doc_from(DOC_A);
        let b: ChainDocument = doc_from(DOC_A);
        assert!(compare(&a, &b).is_empty());
    }

    #[test]
    fn mismatched_output_blake3_is_detected() {
        let a: ChainDocument = doc_from(DOC_A);
        let b: ChainDocument = doc_from(&DOC_A.replace("\"bb\"", "\"cc\""));
        let diffs: Vec<Difference> = compare(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field, "output-blake3");
        assert_eq!(diffs[0].left, "bb");
        assert_eq!(diffs[0].right, "cc");
    }

    #[test]
    fn guard_filters_to_integrity_fields_only() {
        let reference: ChainDocument = doc_from(DOC_A);
        let subject: ChainDocument =
            doc_from(&DOC_A.replace("\"total_ms\": 1", "\"total_ms\": 99"));
        let cosmetic: Vec<Difference> = compare(&reference, &subject);
        assert!(
            cosmetic.is_empty(),
            "total_ms is not a compared field; expected no diffs, got {cosmetic:?}"
        );
    }

    #[test]
    fn guard_detects_blake3_tamper() {
        let reference: ChainDocument = doc_from(DOC_A);
        let subject: ChainDocument = doc_from(&DOC_A.replace("\"bb\"", "\"deadbeef\""));
        let violations: Vec<Difference> = compare(&reference, &subject)
            .into_iter()
            .filter(|d: &Difference| matches!(d.field, "output-blake3" | "presence"))
            .collect();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field, "output-blake3");
    }

    #[test]
    fn missing_node_is_a_presence_difference() {
        let a: ChainDocument = doc_from(DOC_A);
        let mut b: ChainDocument = doc_from(DOC_A);
        b.nodes.clear();
        let diffs: Vec<Difference> = compare(&a, &b);
        assert!(diffs.iter().any(|d: &Difference| d.field == "presence"));
    }
}
