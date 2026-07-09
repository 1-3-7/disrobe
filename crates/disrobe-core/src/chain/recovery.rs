use serde::{Deserialize, Serialize};

use crate::recovery::{ConfidenceTier, TierHistogram};

use super::chain_json::VerdictDoc;
use super::detection::OutputKind;
use super::state_machine::{ChainPlan, Node, Verdict};

pub const RECOVERY_SCHEMA_VERSION: &str = "disrobe.recovery/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryStatus {
    Recovered,
    Advanced,
    Incomplete,
    Failed,
    Skipped,
}

impl RecoveryStatus {
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recovered => "recovered",
            Self::Advanced => "advanced",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryInputDoc {
    pub path: Option<String>,
    pub blake3: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainPassRecovery {
    pub name: String,
    pub status: RecoveryStatus,
    pub confidence: ConfidenceTier,
    pub duration_ms: Option<u128>,
    pub format_in: Option<String>,
    pub format_out: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainRecoveryReport {
    pub schema: String,
    pub tool_version: String,
    pub input: RecoveryInputDoc,
    pub passes: Vec<ChainPassRecovery>,
    pub histogram: TierHistogram,
    pub total_ms: u128,
    pub verdict: VerdictDoc,
}

#[inline]
#[must_use]
pub const fn status_from_node(node: &Node) -> RecoveryStatus {
    match &node.verdict {
        Verdict::Complete { .. } | Verdict::Extracted => RecoveryStatus::Recovered,
        Verdict::Ok | Verdict::FanOut { .. } | Verdict::FanOutPartial { .. } => {
            RecoveryStatus::Advanced
        }
        Verdict::Stalled | Verdict::Cycle | Verdict::CapReached => RecoveryStatus::Incomplete,
        Verdict::Error { .. } => RecoveryStatus::Failed,
        Verdict::DryRun => RecoveryStatus::Skipped,
    }
}

#[inline]
#[must_use]
pub const fn tier_from_node(node: &Node) -> ConfidenceTier {
    match (&node.verdict, node.output_kind.as_ref()) {
        (Verdict::Complete { .. }, Some(OutputKind::Source { .. })) => ConfidenceTier::Semantic,
        (Verdict::Ok, Some(OutputKind::Bytes { .. })) => ConfidenceTier::Partial,
        _ => ConfidenceTier::Skeleton,
    }
}

#[inline]
#[must_use]
fn format_out_of(kind: Option<&OutputKind>) -> Option<String> {
    match kind {
        Some(OutputKind::Source { language, .. }) => Some(language.label().to_string()),
        Some(OutputKind::Bytes { format_tag, .. }) => Some((*format_tag).to_string()),
        Some(OutputKind::Mixed { .. }) => Some("mixed".to_string()),
        None => None,
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s: String = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

impl ChainRecoveryReport {
    #[must_use]
    pub fn from_plan(plan: &ChainPlan, tool_version: &str, input_path: Option<String>) -> Self {
        let passes: Vec<ChainPassRecovery> = plan
            .nodes
            .iter()
            .skip(1)
            .map(|n: &Node| ChainPassRecovery {
                name: n.pass_id.clone().unwrap_or_else(|| "terminal".to_string()),
                status: status_from_node(n),
                confidence: tier_from_node(n),
                duration_ms: n.duration.map(|d: std::time::Duration| d.as_millis()),
                format_in: n.format_tag_in.clone(),
                format_out: format_out_of(n.output_kind.as_ref()),
            })
            .collect();
        let histogram: TierHistogram =
            TierHistogram::from_tiers(passes.iter().map(|p: &ChainPassRecovery| p.confidence));
        let root: &Node = plan.root();
        Self {
            schema: RECOVERY_SCHEMA_VERSION.to_string(),
            tool_version: tool_version.to_string(),
            input: RecoveryInputDoc {
                path: input_path,
                blake3: hex32(&root.input_blake3),
                size: root.input_size,
            },
            passes,
            histogram,
            total_ms: plan.total.as_millis(),
            verdict: VerdictDoc::from(&plan.verdict),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::provenance::Language;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn root_node(input_hash: [u8; 32], size: u64) -> Node {
        Node {
            id: 0,
            parent_id: None,
            depth: 0,
            branch_id: "a".to_string(),
            pass_id: None,
            format_tag_in: None,
            input_blake3: input_hash,
            input_size: size,
            output_kind: None,
            output_blake3: None,
            output_size: None,
            output_bytes: None,
            duration: None,
            picks: Vec::new(),
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
            verdict: Verdict::Ok,
        }
    }

    fn pass_node(
        id: u32,
        pass_id: &str,
        input_hash: [u8; 32],
        output_hash: Option<[u8; 32]>,
        kind: Option<OutputKind>,
        verdict: Verdict,
    ) -> Node {
        Node {
            id,
            parent_id: Some(0),
            depth: 1,
            branch_id: "a".to_string(),
            pass_id: Some(pass_id.to_string()),
            format_tag_in: Some("tag".to_string()),
            input_blake3: input_hash,
            input_size: 16,
            output_kind: kind,
            output_blake3: output_hash,
            output_size: output_hash.map(|_| 16),
            output_bytes: None,
            duration: Some(Duration::from_millis(7)),
            picks: Vec::new(),
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
            verdict,
        }
    }

    fn plan_with(nodes: Vec<Node>, verdict: Verdict) -> ChainPlan {
        ChainPlan {
            nodes,
            root_id: 0,
            verdict,
            final_format: None,
            total: Duration::from_millis(42),
            detector_calls: 0,
            rejected_passes: 0,
            has_multiple_branches: false,
            extracted: Vec::new(),
        }
    }

    #[test]
    fn schema_constant_is_v1() {
        assert_eq!(RECOVERY_SCHEMA_VERSION, "disrobe.recovery/v1");
    }

    #[test]
    fn status_maps_every_verdict() {
        let cases: [(Verdict, RecoveryStatus); 9] = [
            (
                Verdict::Complete {
                    formats: vec!["Python".to_string()],
                },
                RecoveryStatus::Recovered,
            ),
            (Verdict::Ok, RecoveryStatus::Advanced),
            (Verdict::FanOut { count: 2 }, RecoveryStatus::Advanced),
            (
                Verdict::FanOutPartial { ok: 1, total: 2 },
                RecoveryStatus::Advanced,
            ),
            (Verdict::Stalled, RecoveryStatus::Incomplete),
            (Verdict::Cycle, RecoveryStatus::Incomplete),
            (Verdict::CapReached, RecoveryStatus::Incomplete),
            (
                Verdict::Error {
                    message: "boom".to_string(),
                },
                RecoveryStatus::Failed,
            ),
            (Verdict::DryRun, RecoveryStatus::Skipped),
        ];
        for (verdict, expected) in cases {
            let n: Node = pass_node(1, "p", [0u8; 32], None, None, verdict);
            assert_eq!(status_from_node(&n), expected);
        }
    }

    #[test]
    fn tier_semantic_for_formatted_source_chain_never_witnesses_exact() {
        let n: Node = pass_node(
            1,
            "p",
            [1u8; 32],
            Some([2u8; 32]),
            Some(OutputKind::Source {
                language: Language::Python,
                formatted: true,
            }),
            Verdict::Complete {
                formats: vec!["Python".to_string()],
            },
        );
        assert_eq!(tier_from_node(&n), ConfidenceTier::Semantic);
    }

    #[test]
    fn tier_semantic_for_passthrough_or_unformatted_source() {
        let passthrough: Node = pass_node(
            1,
            "p",
            [3u8; 32],
            Some([3u8; 32]),
            Some(OutputKind::Source {
                language: Language::Python,
                formatted: true,
            }),
            Verdict::Complete {
                formats: vec!["Python".to_string()],
            },
        );
        assert_eq!(tier_from_node(&passthrough), ConfidenceTier::Semantic);
        let unformatted: Node = pass_node(
            2,
            "p",
            [1u8; 32],
            Some([2u8; 32]),
            Some(OutputKind::Source {
                language: Language::Python,
                formatted: false,
            }),
            Verdict::Complete {
                formats: vec!["Python".to_string()],
            },
        );
        assert_eq!(tier_from_node(&unformatted), ConfidenceTier::Semantic);
    }

    #[test]
    fn tier_partial_for_bytes_ok() {
        let n: Node = pass_node(
            1,
            "p",
            [1u8; 32],
            Some([2u8; 32]),
            Some(OutputKind::Bytes {
                format_tag: "pyc-3.11",
                family: "interpreter-bytecode",
            }),
            Verdict::Ok,
        );
        assert_eq!(tier_from_node(&n), ConfidenceTier::Partial);
    }

    #[test]
    fn tier_skeleton_for_mixed_fanout_and_for_nothing() {
        let mixed: Node = pass_node(
            1,
            "p",
            [1u8; 32],
            None,
            Some(OutputKind::Mixed { children: vec![] }),
            Verdict::FanOut { count: 0 },
        );
        assert_eq!(tier_from_node(&mixed), ConfidenceTier::Skeleton);
        let errored: Node = pass_node(
            2,
            "p",
            [1u8; 32],
            None,
            None,
            Verdict::Error {
                message: "x".to_string(),
            },
        );
        assert_eq!(tier_from_node(&errored), ConfidenceTier::Skeleton);
    }

    #[test]
    fn histogram_sums_to_pass_count() {
        let root: Node = root_node([0u8; 32], 16);
        let source: Node = pass_node(
            1,
            "py.decompile",
            [1u8; 32],
            Some([2u8; 32]),
            Some(OutputKind::Source {
                language: Language::Python,
                formatted: true,
            }),
            Verdict::Complete {
                formats: vec!["Python".to_string()],
            },
        );
        let bytes: Node = pass_node(
            2,
            "pyarmor.unpack",
            [2u8; 32],
            Some([3u8; 32]),
            Some(OutputKind::Bytes {
                format_tag: "pyc-3.11",
                family: "interpreter-bytecode",
            }),
            Verdict::Ok,
        );
        let failed: Node = pass_node(
            3,
            "nuitka.extract",
            [3u8; 32],
            None,
            None,
            Verdict::Error {
                message: "boom".to_string(),
            },
        );
        let plan: ChainPlan = plan_with(
            vec![root, source, bytes, failed],
            Verdict::FanOutPartial { ok: 1, total: 2 },
        );
        let report: ChainRecoveryReport = ChainRecoveryReport::from_plan(&plan, "9.9.9", None);
        assert_eq!(report.passes.len(), 3);
        assert_eq!(report.histogram.total(), 3);
        assert_eq!(report.histogram.exact, 0);
        assert_eq!(report.histogram.semantic, 1);
        assert_eq!(report.histogram.partial, 1);
        assert_eq!(report.histogram.skeleton, 1);
    }

    #[test]
    fn from_plan_records_real_signals() {
        let root: Node = root_node([0xabu8; 32], 128);
        let source: Node = pass_node(
            1,
            "py.decompile",
            [1u8; 32],
            Some([2u8; 32]),
            Some(OutputKind::Source {
                language: Language::Python,
                formatted: true,
            }),
            Verdict::Complete {
                formats: vec!["Python".to_string()],
            },
        );
        let plan: ChainPlan = plan_with(
            vec![root, source],
            Verdict::Complete {
                formats: vec!["Python".to_string()],
            },
        );
        let report: ChainRecoveryReport =
            ChainRecoveryReport::from_plan(&plan, "9.9.9", Some("in.pyc".to_string()));
        assert_eq!(report.schema, "disrobe.recovery/v1");
        assert_eq!(report.tool_version, "9.9.9");
        assert_eq!(report.input.path.as_deref(), Some("in.pyc"));
        assert_eq!(report.input.blake3.len(), 64);
        assert_eq!(report.input.size, 128);
        assert_eq!(report.total_ms, 42);
        assert_eq!(report.verdict, VerdictDoc::Complete);
        let only: &ChainPassRecovery = &report.passes[0];
        assert_eq!(only.name, "py.decompile");
        assert_eq!(only.status, RecoveryStatus::Recovered);
        assert_eq!(only.confidence, ConfidenceTier::Semantic);
        assert_eq!(only.duration_ms, Some(7));
        assert_eq!(only.format_out.as_deref(), Some("Python"));
    }

    #[test]
    fn terminal_node_without_pass_id_named_terminal() {
        let root: Node = root_node([0u8; 32], 8);
        let terminal: Node = Node {
            pass_id: None,
            ..pass_node(1, "ignored", [1u8; 32], None, None, Verdict::CapReached)
        };
        let plan: ChainPlan = plan_with(vec![root, terminal], Verdict::CapReached);
        let report: ChainRecoveryReport = ChainRecoveryReport::from_plan(&plan, "1.0.0", None);
        assert_eq!(report.passes[0].name, "terminal");
        assert_eq!(report.passes[0].status, RecoveryStatus::Incomplete);
    }

    #[test]
    fn status_serializes_lowercase() {
        let j: String = serde_json::to_string(&RecoveryStatus::Recovered).unwrap();
        assert_eq!(j, "\"recovered\"");
        let parsed: RecoveryStatus = serde_json::from_str("\"failed\"").unwrap();
        assert_eq!(parsed, RecoveryStatus::Failed);
    }

    #[test]
    fn status_ord_is_declaration_order() {
        assert!(RecoveryStatus::Recovered < RecoveryStatus::Advanced);
        assert!(RecoveryStatus::Advanced < RecoveryStatus::Incomplete);
        assert!(RecoveryStatus::Incomplete < RecoveryStatus::Failed);
        assert!(RecoveryStatus::Failed < RecoveryStatus::Skipped);
    }

    #[test]
    fn report_serde_round_trip() {
        let root: Node = root_node([0u8; 32], 4);
        let n: Node = pass_node(
            1,
            "p",
            [1u8; 32],
            Some([2u8; 32]),
            Some(OutputKind::Bytes {
                format_tag: "x",
                family: "y",
            }),
            Verdict::Ok,
        );
        let plan: ChainPlan = plan_with(vec![root, n], Verdict::Ok);
        let report: ChainRecoveryReport = ChainRecoveryReport::from_plan(&plan, "1.2.3", None);
        let j: String = serde_json::to_string(&report).unwrap();
        let parsed: ChainRecoveryReport = serde_json::from_str(&j).unwrap();
        assert_eq!(parsed, report);
    }
}
