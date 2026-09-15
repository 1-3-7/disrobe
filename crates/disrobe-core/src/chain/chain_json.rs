use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::detection::{ChildHandle, ConfidenceBand, OutputKind};
use super::metadata_keys;
use super::metadata_keys::MetadataValueError;
use super::metadata_keys::keys;
use super::spec::SpecKind;
use super::state_machine::{ChainPlan, Node, NodeId, Verdict};

pub const SCHEMA_VERSION: &str = "disrobe.chain/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Topology {
    Linear,
    Tree,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInputDoc {
    pub path: Option<String>,
    pub blake3: String,
    pub size: u64,
    pub detected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSpecDoc {
    pub raw: String,
    pub kind: SpecKind,
    pub cap: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum OutputKindDoc {
    Source { language: String, formatted: bool },
    Bytes { format_tag: String, family: String },
    Report { format_tag: String, family: String },
    Mixed { children: Vec<ChildHandle> },
}

impl From<&OutputKind> for OutputKindDoc {
    fn from(k: &OutputKind) -> Self {
        match k {
            OutputKind::Source {
                language,
                formatted,
            } => Self::Source {
                language: language.label().to_string(),
                formatted: *formatted,
            },
            OutputKind::Bytes { format_tag, family } => Self::Bytes {
                format_tag: (*format_tag).to_string(),
                family: (*family).to_string(),
            },
            OutputKind::Report { format_tag, family } => Self::Report {
                format_tag: (*format_tag).to_string(),
                family: (*family).to_string(),
            },
            OutputKind::Mixed { children } => Self::Mixed {
                children: children.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorPickDoc {
    pub pass_id: String,
    pub format_tag: String,
    pub family: String,
    pub confidence: f32,
    pub band: ConfidenceBand,
    pub specificity: u16,
    pub markers: Vec<String>,
    pub explain: String,
    pub chosen: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDoc {
    pub id: NodeId,
    pub parent_id: Option<NodeId>,
    pub depth: u8,
    pub branch_id: String,
    pub pass: Option<String>,
    pub format_tag_in: Option<String>,
    pub input_blake3: String,
    pub input_size: u64,
    pub output_kind: Option<OutputKindDoc>,
    pub output_blake3: Option<String>,
    pub output_size: Option<u64>,
    pub duration_ms: Option<u128>,
    pub detector_picks: Vec<DetectorPickDoc>,
    pub artifacts: Vec<String>,
    pub metadata: BTreeMap<String, String>,
    pub rule_pack_id: Option<String>,
    pub verdict: VerdictDoc,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictDoc {
    Ok,
    Complete,
    FanOut,
    FanOutPartial,
    Stalled,
    Cycle,
    CapReached,
    Extracted,
    Error,
    DryRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictGrade {
    Ok,
    Incomplete,
    Failed,
}

impl VerdictGrade {
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
        }
    }

    #[inline]
    #[must_use]
    pub const fn meets(self, threshold: VerdictThreshold) -> bool {
        match threshold {
            VerdictThreshold::Never => false,
            VerdictThreshold::Incomplete | VerdictThreshold::Any => {
                matches!(self, Self::Incomplete | Self::Failed)
            }
            VerdictThreshold::Failed => matches!(self, Self::Failed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum VerdictThreshold {
    Never,
    Incomplete,
    Failed,
    Any,
}

impl VerdictThreshold {
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
            Self::Any => "any",
        }
    }

    #[inline]
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "never" => Some(Self::Never),
            "incomplete" => Some(Self::Incomplete),
            "failed" => Some(Self::Failed),
            "any" => Some(Self::Any),
            _ => None,
        }
    }
}

impl VerdictDoc {
    #[inline]
    #[must_use]
    pub const fn grade(&self) -> VerdictGrade {
        match self {
            Self::Ok | Self::Complete | Self::FanOut | Self::Extracted => VerdictGrade::Ok,
            Self::FanOutPartial | Self::Stalled | Self::Cycle | Self::CapReached | Self::DryRun => {
                VerdictGrade::Incomplete
            }
            Self::Error => VerdictGrade::Failed,
        }
    }
}

impl From<&Verdict> for VerdictDoc {
    fn from(v: &Verdict) -> Self {
        match v {
            Verdict::Ok => Self::Ok,
            Verdict::Complete { .. } => Self::Complete,
            Verdict::FanOut { .. } => Self::FanOut,
            Verdict::FanOutPartial { .. } => Self::FanOutPartial,
            Verdict::Stalled => Self::Stalled,
            Verdict::Cycle => Self::Cycle,
            Verdict::CapReached => Self::CapReached,
            Verdict::Extracted => Self::Extracted,
            Verdict::Error { .. } => Self::Error,
            Verdict::DryRun => Self::DryRun,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStats {
    pub layers: u32,
    pub branches: u32,
    pub total_ms: u128,
    pub max_branch_depth: u8,
    pub detector_calls: u32,
    pub rejected_passes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainDocument {
    pub schema: String,
    pub tool_version: String,
    pub input: ChainInputDoc,
    pub spec: ChainSpecDoc,
    pub topology: Topology,
    pub root_node_id: NodeId,
    pub nodes: Vec<NodeDoc>,
    pub verdict: VerdictDoc,
    pub final_format: Option<String>,
    pub stats: ChainStats,
}

impl ChainDocument {
    pub fn from_plan(
        plan: &ChainPlan,
        spec: &super::spec::ChainSpec,
        raw_spec: &str,
        tool_version: &str,
        input_path: Option<String>,
    ) -> Result<Self, MetadataValueError> {
        let root: &Node = plan.root();
        let topology: Topology = if plan.has_multiple_branches {
            Topology::Tree
        } else {
            Topology::Linear
        };
        let detected: Vec<String> = plan
            .nodes
            .iter()
            .skip(1)
            .filter_map(|n: &Node| n.format_tag_in.clone())
            .collect();
        let nodes: Vec<NodeDoc> = plan
            .nodes
            .iter()
            .map(NodeDoc::from_node)
            .collect::<Result<Vec<NodeDoc>, MetadataValueError>>()?;
        let stats: ChainStats = ChainStats {
            layers: u32::try_from(plan.nodes.len().saturating_sub(1)).unwrap_or(u32::MAX),
            branches: plan.branch_count(),
            total_ms: plan.total.as_millis(),
            max_branch_depth: plan.max_branch_depth(),
            detector_calls: plan.detector_calls,
            rejected_passes: plan.rejected_passes,
        };
        Ok(Self {
            schema: SCHEMA_VERSION.to_string(),
            tool_version: tool_version.to_string(),
            input: ChainInputDoc {
                path: input_path,
                blake3: hex32(&root.input_blake3),
                size: root.input_size,
                detected,
            },
            spec: ChainSpecDoc {
                raw: raw_spec.to_string(),
                kind: spec.kind(),
                cap: spec.cap(),
            },
            topology,
            root_node_id: plan.root_id,
            nodes,
            verdict: VerdictDoc::from(&plan.verdict),
            final_format: plan.final_format.clone(),
            stats,
        })
    }
}

impl NodeDoc {
    fn from_node(n: &Node) -> Result<Self, MetadataValueError> {
        let error: Option<String> = match &n.verdict {
            Verdict::Error { message } => Some(message.clone()),
            _ => None,
        };
        let rule_pack_id: Option<String> = n.rule_pack_id()?;
        let mut document: Self = Self {
            id: n.id,
            parent_id: n.parent_id,
            depth: n.depth,
            branch_id: n.branch_id.clone(),
            pass: n.pass_id.clone(),
            format_tag_in: n.format_tag_in.clone(),
            input_blake3: hex32(&n.input_blake3),
            input_size: n.input_size,
            output_kind: n.output_kind.as_ref().map(OutputKindDoc::from),
            output_blake3: n.output_blake3.as_ref().map(|h: &[u8; 32]| hex32(h)),
            output_size: n.output_size,
            duration_ms: n.duration.map(|d: std::time::Duration| d.as_millis()),
            detector_picks: n
                .picks
                .iter()
                .map(|p: &super::registry::DetectorPick| DetectorPickDoc {
                    pass_id: p.verdict.pass_id.to_string(),
                    format_tag: p.verdict.format_tag.to_string(),
                    family: p.verdict.family.to_string(),
                    confidence: p.verdict.confidence,
                    band: p.verdict.band,
                    specificity: p.verdict.specificity,
                    markers: p
                        .verdict
                        .markers
                        .iter()
                        .map(|s: &&str| (*s).to_string())
                        .collect(),
                    explain: p.verdict.explain.clone(),
                    chosen: true,
                })
                .collect(),
            artifacts: n.artifacts.clone(),
            metadata: n.metadata.clone(),
            rule_pack_id,
            verdict: VerdictDoc::from(&n.verdict),
            error,
        };
        if let Some(value) = document.rule_pack_id.clone() {
            document.set_rule_pack_id(&value)?;
        }
        Ok(document)
    }

    fn set_rule_pack_id(&mut self, value: &str) -> Result<(), MetadataValueError> {
        let _previous: Option<String> =
            metadata_keys::set_string(&mut self.metadata, keys::MBA_RULE_PACK_ID_KEY, value)?;
        Ok(())
    }
}

impl Node {
    fn rule_pack_id(&self) -> Result<Option<String>, MetadataValueError> {
        metadata_keys::get_string(&self.metadata, keys::MBA_RULE_PACK_ID_KEY)
            .map(|value: Option<&str>| value.map(str::to_owned))
    }
}

use crate::codec::hex::encode as hex32;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn hex32_round_trip_zero() {
        let h: String = hex32(&[0u8; 32]);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c: char| c == '0'));
    }

    #[test]
    fn hex32_alphabet() {
        let mut b: [u8; 32] = [0u8; 32];
        b[0] = 0xab;
        b[31] = 0xcd;
        let h: String = hex32(&b);
        assert!(h.starts_with("ab"));
        assert!(h.ends_with("cd"));
    }

    #[test]
    fn schema_constant_is_v1() {
        assert_eq!(SCHEMA_VERSION, "disrobe.chain/v1");
    }

    #[test]
    fn topology_serializes_lowercase() {
        let j: String = serde_json::to_string(&Topology::Tree).unwrap();
        assert_eq!(j, "\"tree\"");
        let j2: String = serde_json::to_string(&Topology::Linear).unwrap();
        assert_eq!(j2, "\"linear\"");
    }

    #[test]
    fn verdict_doc_serialises_kebab() {
        let j: String = serde_json::to_string(&VerdictDoc::CapReached).unwrap();
        assert_eq!(j, "\"cap-reached\"");
    }

    #[test]
    fn node_doc_roundtrip_minimum() {
        let n: Node = Node {
            id: 0,
            parent_id: None,
            depth: 0,
            branch_id: "a".to_string(),
            pass_id: None,
            format_tag_in: None,
            input_blake3: [0u8; 32],
            input_size: 0,
            output_kind: None,
            output_blake3: None,
            output_size: None,
            output_bytes: None,
            duration: None,
            picks: vec![],
            artifacts: vec![],
            metadata: BTreeMap::new(),
            verdict: Verdict::Ok,
        };
        let doc: NodeDoc = NodeDoc::from_node(&n).expect("valid node metadata");
        let j: String = serde_json::to_string(&doc).unwrap();
        let parsed: NodeDoc = serde_json::from_str(&j).unwrap();
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.branch_id, "a");
        assert_eq!(parsed.verdict, VerdictDoc::Ok);
    }

    #[test]
    fn chain_document_from_plan_records_schema() {
        use super::super::spec::ChainSpec;
        let plan: ChainPlan = ChainPlan {
            nodes: vec![Node {
                id: 0,
                parent_id: None,
                depth: 0,
                branch_id: "a".to_string(),
                pass_id: None,
                format_tag_in: None,
                input_blake3: [0u8; 32],
                input_size: 0,
                output_kind: None,
                output_blake3: None,
                output_size: None,
                output_bytes: None,
                duration: None,
                picks: vec![],
                artifacts: vec![],
                metadata: BTreeMap::new(),
                verdict: Verdict::Stalled,
            }],
            root_id: 0,
            verdict: Verdict::Stalled,
            final_format: None,
            total: Duration::from_millis(0),
            detector_calls: 0,
            rejected_passes: 0,
            has_multiple_branches: false,
            extracted: Vec::new(),
        };
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let doc: ChainDocument = ChainDocument::from_plan(&plan, &spec, "auto:8", "0.1.0", None)
            .expect("valid chain metadata");
        assert_eq!(doc.schema, "disrobe.chain/v1");
        assert_eq!(doc.spec.cap, 8);
        assert!(matches!(doc.topology, Topology::Linear));
        assert_eq!(doc.verdict, VerdictDoc::Stalled);
        let j: String = serde_json::to_string(&doc).unwrap();
        assert!(
            j.contains("\"topology\":\"linear\""),
            "the topology JSON key and Linear text must be byte-for-byte unchanged: {j}"
        );
        let parsed: ChainDocument = serde_json::from_str(&j).unwrap();
        assert_eq!(parsed.schema, "disrobe.chain/v1");
    }

    #[test]
    fn chain_document_topology_is_tree_for_multiple_branches() {
        use super::super::spec::ChainSpec;
        let node: Node = Node {
            id: 0,
            parent_id: None,
            depth: 0,
            branch_id: "a".to_string(),
            pass_id: None,
            format_tag_in: None,
            input_blake3: [0u8; 32],
            input_size: 0,
            output_kind: None,
            output_blake3: None,
            output_size: None,
            output_bytes: None,
            duration: None,
            picks: vec![],
            artifacts: vec![],
            metadata: BTreeMap::new(),
            verdict: Verdict::Ok,
        };
        let plan: ChainPlan = ChainPlan {
            nodes: vec![node],
            root_id: 0,
            verdict: Verdict::Ok,
            final_format: None,
            total: Duration::from_millis(0),
            detector_calls: 0,
            rejected_passes: 0,
            has_multiple_branches: true,
            extracted: Vec::new(),
        };
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let doc: ChainDocument = ChainDocument::from_plan(&plan, &spec, "auto:8", "0.1.0", None)
            .expect("valid chain metadata");
        assert!(matches!(doc.topology, Topology::Tree));
        let j: String = serde_json::to_string(&doc).unwrap();
        assert!(
            j.contains("\"topology\":\"tree\""),
            "the topology JSON key and Tree text must be byte-for-byte unchanged: {j}"
        );
    }

    #[test]
    fn chain_document_preserves_and_bounds_rule_pack_metadata() {
        use super::super::spec::ChainSpec;

        let value: &str = "mba-peephole/2026-08";
        let mut valid_metadata: BTreeMap<String, String> = BTreeMap::new();
        valid_metadata.insert(keys::MBA_RULE_PACK_ID.to_string(), value.to_string());
        let valid_plan: ChainPlan = chain_plan_with_metadata(valid_metadata);
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let document: ChainDocument =
            ChainDocument::from_plan(&valid_plan, &spec, "auto:8", "0.1.0", None)
                .expect("valid rule-pack metadata");
        assert_eq!(document.nodes[0].rule_pack_id.as_deref(), Some(value));
        assert_eq!(
            metadata_keys::get_string(&document.nodes[0].metadata, keys::MBA_RULE_PACK_ID_KEY)
                .expect("bounded rule-pack metadata"),
            Some(value)
        );

        let oversized: String = "x".repeat(keys::MBA_RULE_PACK_ID_KEY.max_bytes() + 1);
        let invalid_plan: ChainPlan = chain_plan_with_metadata(BTreeMap::from([(
            keys::MBA_RULE_PACK_ID.to_string(),
            oversized,
        )]));
        let error: MetadataValueError =
            ChainDocument::from_plan(&invalid_plan, &spec, "auto:8", "0.1.0", None)
                .expect_err("oversized rule-pack metadata must be rejected");
        assert_eq!(
            error,
            MetadataValueError::ValueTooLong {
                key: keys::MBA_RULE_PACK_ID,
                actual_bytes: keys::MBA_RULE_PACK_ID_KEY.max_bytes() + 1,
                max_bytes: keys::MBA_RULE_PACK_ID_KEY.max_bytes(),
            }
        );
    }

    fn chain_plan_with_metadata(metadata: BTreeMap<String, String>) -> ChainPlan {
        ChainPlan {
            nodes: vec![Node {
                id: 0,
                parent_id: None,
                depth: 0,
                branch_id: "a".to_string(),
                pass_id: None,
                format_tag_in: None,
                input_blake3: [0u8; 32],
                input_size: 0,
                output_kind: None,
                output_blake3: None,
                output_size: None,
                output_bytes: None,
                duration: None,
                picks: vec![],
                artifacts: vec![],
                metadata,
                verdict: Verdict::Ok,
            }],
            root_id: 0,
            verdict: Verdict::Ok,
            final_format: None,
            total: Duration::ZERO,
            detector_calls: 0,
            rejected_passes: 0,
            has_multiple_branches: false,
            extracted: Vec::new(),
        }
    }

    #[test]
    fn output_kind_doc_from_source() {
        use crate::provenance::Language;
        let k: OutputKind = OutputKind::Source {
            language: Language::Python,
            formatted: true,
        };
        let d: OutputKindDoc = OutputKindDoc::from(&k);
        let j: String = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"source\""));
        assert!(j.contains("\"Python\""));
    }

    #[test]
    fn output_kind_doc_from_bytes() {
        let k: OutputKind = OutputKind::Bytes {
            format_tag: "pyc-3.11",
            family: "interpreter-bytecode",
        };
        let d: OutputKindDoc = OutputKindDoc::from(&k);
        let j: String = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"bytes\""));
        assert!(j.contains("pyc-3.11"));
    }

    #[test]
    fn output_kind_doc_from_mixed_empty() {
        let k: OutputKind = OutputKind::Mixed { children: vec![] };
        let d: OutputKindDoc = OutputKindDoc::from(&k);
        let j: String = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"mixed\""));
    }
}
