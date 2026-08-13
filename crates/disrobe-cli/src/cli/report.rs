#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use disrobe_core::chain::{ChainDocument, ChainRecoveryReport, NodeDoc, VerdictDoc};
use disrobe_core::recovery::ConfidenceTier;
use serde::Serialize;

use super::batch::{self, BatchManifest, BatchOptions};
use super::chain_v1::{self, ChainOutcome};
use super::output::OutputFormat;
use super::sarif::artifact_uri;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ReportFormat {
    #[default]
    Text,
    Json,
    Markdown,
    Html,
    Sarif,
}

#[derive(Debug, Serialize)]
pub(crate) struct StageView {
    pub(crate) index: usize,
    pub(crate) node_id: u32,
    pub(crate) pass: String,
    pub(crate) verdict: String,
    pub(crate) confidence: &'static str,
    pub(crate) recovery_score: f64,
    pub(crate) duration_ms: Option<u128>,
    pub(crate) format_in: Option<String>,
    pub(crate) format_out: Option<String>,
    pub(crate) artifacts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WallKind {
    NoPassAccepted,
    EmptyPassOutput,
    RepeatedArtifact,
    DepthCapReached,
    NotExecuted,
    BranchesIncomplete,
}

impl WallKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NoPassAccepted => "no-pass-accepted",
            Self::EmptyPassOutput => "empty-pass-output",
            Self::RepeatedArtifact => "repeated-artifact",
            Self::DepthCapReached => "depth-cap-reached",
            Self::NotExecuted => "not-executed",
            Self::BranchesIncomplete => "branches-incomplete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct WallView {
    pub(crate) kind: WallKind,
    pub(crate) node_id: u32,
    pub(crate) stage_index: Option<usize>,
    pub(crate) pass: Option<String>,
    pub(crate) format_in: Option<String>,
    pub(crate) missing: String,
    pub(crate) artifact_blake3: String,
    pub(crate) artifact_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct FailureView {
    pub(crate) node_id: u32,
    pub(crate) stage_index: Option<usize>,
    pub(crate) pass: Option<String>,
    pub(crate) message: String,
    pub(crate) artifact_blake3: String,
    pub(crate) artifact_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EvidenceRole {
    AnalysisTarget,
    StageInput,
    StageOutput,
    RecoveredArtifact,
}

impl EvidenceRole {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::AnalysisTarget => "analysis-target",
            Self::StageInput => "stage-input",
            Self::StageOutput => "stage-output",
            Self::RecoveredArtifact => "recovered-artifact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HashSource {
    ChainDocument,
    RecomputedFromFile,
    Unavailable,
}

impl HashSource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ChainDocument => "chain-document",
            Self::RecomputedFromFile => "recomputed-from-file",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct EvidenceItem {
    pub(crate) role: EvidenceRole,
    pub(crate) uri: String,
    pub(crate) display: String,
    pub(crate) blake3: Option<String>,
    pub(crate) hash_source: HashSource,
    pub(crate) byte_offset: u64,
    pub(crate) byte_length: Option<u64>,
    pub(crate) stage_index: Option<usize>,
    pub(crate) node_id: Option<u32>,
    pub(crate) unavailable_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Reproduction {
    pub(crate) command: String,
    pub(crate) steps: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InputIdentity {
    pub(crate) path: Option<String>,
    pub(crate) size: u64,
    pub(crate) blake3: String,
    pub(crate) detected: Vec<String>,
    pub(crate) final_format: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TierTotals {
    pub(crate) exact: u32,
    pub(crate) semantic: u32,
    pub(crate) partial: u32,
    pub(crate) skeleton: u32,
    pub(crate) total: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct SingleReport {
    pub(crate) kind: &'static str,
    pub(crate) schema: String,
    pub(crate) tool_version: String,
    pub(crate) source_dir: Option<String>,
    pub(crate) input: InputIdentity,
    pub(crate) topology: String,
    pub(crate) verdict: String,
    pub(crate) total_ms: u128,
    pub(crate) recovery_score: f64,
    pub(crate) tiers: TierTotals,
    pub(crate) stages: Vec<StageView>,
    pub(crate) walls: Vec<WallView>,
    pub(crate) failures: Vec<FailureView>,
    pub(crate) evidence: Vec<EvidenceItem>,
    pub(crate) reproduction: Reproduction,
    pub(crate) artifacts: Vec<String>,
    pub(crate) notes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "report_kind", rename_all = "snake_case")]
pub(crate) enum ReportDocument {
    Single(Box<SingleReport>),
    Batch(Box<BatchReport>),
}

#[derive(Debug, Serialize)]
pub(crate) struct BatchFileView {
    pub(crate) relative: String,
    pub(crate) detected_format: Option<String>,
    pub(crate) chain: Vec<String>,
    pub(crate) verdict: Option<String>,
    pub(crate) recovery_score: Option<f64>,
    pub(crate) duration_ms: u128,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BatchReport {
    pub(crate) schema: String,
    pub(crate) tool_version: String,
    pub(crate) source_dir: String,
    pub(crate) root: String,
    pub(crate) chain: String,
    pub(crate) processed: usize,
    pub(crate) recovered: usize,
    pub(crate) detect_only: usize,
    pub(crate) errors: usize,
    pub(crate) mean_recovery_score: Option<f64>,
    pub(crate) files: Vec<BatchFileView>,
}

const RECOVERY_REPORT_SCHEMA: &str = "disrobe.report/v1";

pub(crate) fn tier_label(score: f64) -> &'static str {
    if score >= 0.99 {
        "exact"
    } else if score >= 0.66 {
        "semantic"
    } else if score >= 0.33 {
        "partial"
    } else {
        "skeleton"
    }
}

fn pass_score(pass: &disrobe_core::chain::ChainPassRecovery) -> f64 {
    f64::from(pass.confidence.rank()) / f64::from(ConfidenceTier::Exact.rank())
}

fn mean_score(report: &ChainRecoveryReport) -> f64 {
    if report.passes.is_empty() {
        return 0.0;
    }
    let sum: f64 = report.passes.iter().map(pass_score).sum();
    (sum / report.passes.len() as f64).clamp(0.0, 1.0)
}

const TERMINAL_PASS_NAME: &str = "terminal";
const CONTENT_URI_SCHEME: &str = "ni:///blake3;";

fn node_matches_pass(node: &NodeDoc, pass_name: &str) -> bool {
    node.pass.as_deref().map_or_else(
        || pass_name == TERMINAL_PASS_NAME,
        |name: &str| name == pass_name,
    )
}

fn attribute_stages<'doc>(
    doc: &'doc ChainDocument,
    recovery: &ChainRecoveryReport,
) -> Vec<Option<&'doc NodeDoc>> {
    let positional: bool = doc.nodes.len() == recovery.passes.len().saturating_add(1)
        && recovery.passes.iter().enumerate().all(
            |(index, pass): (usize, &disrobe_core::chain::ChainPassRecovery)| {
                doc.nodes
                    .get(index.saturating_add(1))
                    .is_some_and(|node: &NodeDoc| node_matches_pass(node, &pass.name))
            },
        );
    if positional {
        return (0..recovery.passes.len())
            .map(|index: usize| doc.nodes.get(index.saturating_add(1)))
            .collect();
    }
    let mut claimed: Vec<bool> = vec![false; doc.nodes.len()];
    recovery
        .passes
        .iter()
        .map(|pass: &disrobe_core::chain::ChainPassRecovery| {
            let found: Option<(usize, &NodeDoc)> =
                doc.nodes
                    .iter()
                    .enumerate()
                    .find(|(index, node): &(usize, &'doc NodeDoc)| {
                        !claimed[*index] && node_matches_pass(node, &pass.name)
                    });
            found.map(|(index, node): (usize, &'doc NodeDoc)| {
                claimed[index] = true;
                node
            })
        })
        .collect()
}

const fn wall_kind_for(node: &NodeDoc) -> Option<WallKind> {
    match node.verdict {
        VerdictDoc::Stalled => Some(if node.pass.is_some() {
            WallKind::EmptyPassOutput
        } else {
            WallKind::NoPassAccepted
        }),
        VerdictDoc::Cycle => Some(WallKind::RepeatedArtifact),
        VerdictDoc::CapReached => Some(WallKind::DepthCapReached),
        VerdictDoc::DryRun => Some(WallKind::NotExecuted),
        VerdictDoc::FanOutPartial => Some(WallKind::BranchesIncomplete),
        VerdictDoc::Ok
        | VerdictDoc::Complete
        | VerdictDoc::FanOut
        | VerdictDoc::Extracted
        | VerdictDoc::Error => None,
    }
}

fn missing_input_for(kind: WallKind, node: &NodeDoc, cap: u8) -> String {
    let format: &str = node.format_tag_in.as_deref().unwrap_or("an unnamed format");
    match kind {
        WallKind::NoPassAccepted => format!(
            "no registered detector claimed the {} byte artifact blake3 {}",
            node.input_size, node.input_blake3
        ),
        WallKind::EmptyPassOutput => format!(
            "pass `{}` accepted {format} and returned no output bytes",
            node.pass.as_deref().unwrap_or(TERMINAL_PASS_NAME)
        ),
        WallKind::RepeatedArtifact => format!(
            "the output of this layer repeats an artifact already seen on branch `{}`",
            node.branch_id
        ),
        WallKind::DepthCapReached => {
            format!(
                "the chain reached its depth cap of {cap} layers at depth {}",
                node.depth
            )
        }
        WallKind::NotExecuted => format!(
            "the run was a dry run, so pass `{}` was selected but never executed",
            node.pass.as_deref().unwrap_or(TERMINAL_PASS_NAME)
        ),
        WallKind::BranchesIncomplete => {
            "at least one branch of this fan-out did not reach a recovered format".to_string()
        }
    }
}

fn collect_walls(
    doc: &ChainDocument,
    stage_nodes: &[Option<&NodeDoc>],
) -> (Vec<WallView>, Vec<FailureView>) {
    let stage_of: Vec<Option<usize>> = doc
        .nodes
        .iter()
        .map(|node: &NodeDoc| {
            stage_nodes
                .iter()
                .copied()
                .position(|attached: Option<&NodeDoc>| {
                    attached.is_some_and(|other: &NodeDoc| other.id == node.id)
                })
                .map(|index: usize| index.saturating_add(1))
        })
        .collect();
    let mut walls: Vec<WallView> = Vec::new();
    let mut failures: Vec<FailureView> = Vec::new();
    for (index, node) in doc.nodes.iter().enumerate() {
        let stage_index: Option<usize> = stage_of.get(index).copied().flatten();
        if node.verdict == VerdictDoc::Error {
            failures.push(FailureView {
                node_id: node.id,
                stage_index,
                pass: node.pass.clone(),
                message: node
                    .error
                    .clone()
                    .unwrap_or_else(|| "the layer failed without a recorded message".to_string()),
                artifact_blake3: node.input_blake3.clone(),
                artifact_size: node.input_size,
            });
            continue;
        }
        let Some(kind): Option<WallKind> = wall_kind_for(node) else {
            continue;
        };
        walls.push(WallView {
            kind,
            node_id: node.id,
            stage_index,
            pass: node.pass.clone(),
            format_in: node.format_tag_in.clone(),
            missing: missing_input_for(kind, node, doc.spec.cap),
            artifact_blake3: node.input_blake3.clone(),
            artifact_size: node.input_size,
        });
    }
    if walls.is_empty() && failures.is_empty() {
        let root: Option<&NodeDoc> = doc
            .nodes
            .iter()
            .find(|n: &&NodeDoc| n.id == doc.root_node_id);
        let kind: Option<WallKind> = document_wall_kind(&doc.verdict);
        if let (Some(root), Some(kind)) = (root, kind) {
            walls.push(WallView {
                kind,
                node_id: root.id,
                stage_index: None,
                pass: None,
                format_in: root.format_tag_in.clone(),
                missing: missing_input_for(kind, root, doc.spec.cap),
                artifact_blake3: root.input_blake3.clone(),
                artifact_size: root.input_size,
            });
        }
    }
    walls.sort();
    failures.sort();
    (walls, failures)
}

const fn document_wall_kind(verdict: &VerdictDoc) -> Option<WallKind> {
    match verdict {
        VerdictDoc::Stalled => Some(WallKind::NoPassAccepted),
        VerdictDoc::Cycle => Some(WallKind::RepeatedArtifact),
        VerdictDoc::CapReached => Some(WallKind::DepthCapReached),
        VerdictDoc::DryRun => Some(WallKind::NotExecuted),
        VerdictDoc::FanOutPartial => Some(WallKind::BranchesIncomplete),
        VerdictDoc::Ok
        | VerdictDoc::Complete
        | VerdictDoc::FanOut
        | VerdictDoc::Extracted
        | VerdictDoc::Error => None,
    }
}

fn content_uri(blake3: &str) -> String {
    format!("{CONTENT_URI_SCHEME}{blake3}")
}

fn hash_artifact_file(path: &Path) -> Result<(String, u64), String> {
    let file: std::fs::File =
        std::fs::File::open(path).map_err(|e: std::io::Error| e.to_string())?;
    let length: u64 = file
        .metadata()
        .map_err(|e: std::io::Error| e.to_string())?
        .len();
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    hasher
        .update_reader(file)
        .map_err(|e: std::io::Error| e.to_string())?;
    Ok((hasher.finalize().to_hex().to_string(), length))
}

fn artifact_evidence(relative: &str, source_dir: Option<&Path>) -> EvidenceItem {
    let resolved: Option<PathBuf> = source_dir.map(|dir: &Path| dir.join(relative));
    let existing: Option<PathBuf> = resolved
        .filter(|p: &PathBuf| p.is_file())
        .or_else(|| Some(PathBuf::from(relative)).filter(|p: &PathBuf| p.is_file()));
    existing.map_or_else(
        || EvidenceItem {
            role: EvidenceRole::RecoveredArtifact,
            uri: artifact_uri(Path::new(relative)),
            display: relative.to_string(),
            blake3: None,
            hash_source: HashSource::Unavailable,
            byte_offset: 0,
            byte_length: None,
            stage_index: None,
            node_id: None,
            unavailable_reason: Some(source_dir.map_or_else(
                || format!("`{relative}` is not on disk and no run directory was given"),
                |dir: &Path| format!("`{relative}` is not on disk under {}", dir.display()),
            )),
        },
        |path: PathBuf| {
            let uri: String = artifact_uri(&path);
            hash_artifact_file(&path).map_or_else(
                |reason: String| EvidenceItem {
                    role: EvidenceRole::RecoveredArtifact,
                    uri: uri.clone(),
                    display: relative.to_string(),
                    blake3: None,
                    hash_source: HashSource::Unavailable,
                    byte_offset: 0,
                    byte_length: None,
                    stage_index: None,
                    node_id: None,
                    unavailable_reason: Some(format!("cannot hash {}: {reason}", path.display())),
                },
                |(blake3, length): (String, u64)| EvidenceItem {
                    role: EvidenceRole::RecoveredArtifact,
                    uri: uri.clone(),
                    display: relative.to_string(),
                    blake3: Some(blake3),
                    hash_source: HashSource::RecomputedFromFile,
                    byte_offset: 0,
                    byte_length: Some(length),
                    stage_index: None,
                    node_id: None,
                    unavailable_reason: None,
                },
            )
        },
    )
}

const EXTRACTED_DIR: &str = "extracted";
const MAX_CITED_ARTIFACTS: usize = 4_096;
const MAX_ARTIFACT_WALK_DEPTH: u32 = 32;

fn walk_extracted(source_dir: Option<&Path>) -> (Vec<String>, Option<String>) {
    let Some(root): Option<PathBuf> = source_dir.map(|dir: &Path| dir.join(EXTRACTED_DIR)) else {
        return (Vec::new(), None);
    };
    if !root.is_dir() {
        return (Vec::new(), None);
    }
    let mut pending: Vec<(PathBuf, u32)> = vec![(root.clone(), 0)];
    let mut found: Vec<String> = Vec::new();
    let mut truncated: Option<String> = None;
    while let Some((dir, depth)) = pending.pop() {
        let Ok(entries): Result<std::fs::ReadDir, std::io::Error> = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut children: Vec<(PathBuf, bool)> = Vec::new();
        for entry in entries.flatten() {
            let Ok(kind): Result<std::fs::FileType, std::io::Error> = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            children.push((entry.path(), kind.is_dir()));
        }
        children.sort();
        for (path, is_dir) in children {
            if is_dir {
                if depth >= MAX_ARTIFACT_WALK_DEPTH {
                    truncated = Some(format!(
                        "the recovered-artifact walk stopped at depth {MAX_ARTIFACT_WALK_DEPTH}; deeper files under `{EXTRACTED_DIR}` are not cited"
                    ));
                    continue;
                }
                pending.push((path, depth.saturating_add(1)));
                continue;
            }
            if found.len() >= MAX_CITED_ARTIFACTS {
                truncated = Some(format!(
                    "the recovered-artifact walk stopped at {MAX_CITED_ARTIFACTS} files; the rest under `{EXTRACTED_DIR}` are not cited"
                ));
                break;
            }
            if let Some(relative) = path
                .strip_prefix(root.parent().unwrap_or(&root))
                .ok()
                .and_then(|p: &Path| p.to_str())
            {
                found.push(relative.replace('\\', "/"));
            }
        }
        if truncated.is_some() && found.len() >= MAX_CITED_ARTIFACTS {
            break;
        }
    }
    found.sort();
    found.dedup();
    (found, truncated)
}

fn collect_evidence(
    doc: &ChainDocument,
    stage_nodes: &[Option<&NodeDoc>],
    artifacts: &[String],
    source_dir: Option<&Path>,
) -> Vec<EvidenceItem> {
    let mut items: Vec<EvidenceItem> = Vec::new();
    items.push(EvidenceItem {
        role: EvidenceRole::AnalysisTarget,
        uri: doc.input.path.as_deref().map_or_else(
            || content_uri(&doc.input.blake3),
            |p: &str| artifact_uri(Path::new(p)),
        ),
        display: doc
            .input
            .path
            .clone()
            .unwrap_or_else(|| content_uri(&doc.input.blake3)),
        blake3: Some(doc.input.blake3.clone()),
        hash_source: HashSource::ChainDocument,
        byte_offset: 0,
        byte_length: Some(doc.input.size),
        stage_index: None,
        node_id: Some(doc.root_node_id),
        unavailable_reason: None,
    });
    for (index, attached) in stage_nodes.iter().enumerate() {
        let Some(node): Option<&NodeDoc> = *attached else {
            continue;
        };
        let stage_index: Option<usize> = Some(index.saturating_add(1));
        items.push(EvidenceItem {
            role: EvidenceRole::StageInput,
            uri: content_uri(&node.input_blake3),
            display: format!("node {} input", node.id),
            blake3: Some(node.input_blake3.clone()),
            hash_source: HashSource::ChainDocument,
            byte_offset: 0,
            byte_length: Some(node.input_size),
            stage_index,
            node_id: Some(node.id),
            unavailable_reason: None,
        });
        if let Some(out_hash) = node.output_blake3.as_deref() {
            items.push(EvidenceItem {
                role: EvidenceRole::StageOutput,
                uri: content_uri(out_hash),
                display: format!("node {} output", node.id),
                blake3: Some(out_hash.to_string()),
                hash_source: HashSource::ChainDocument,
                byte_offset: 0,
                byte_length: node.output_size,
                stage_index,
                node_id: Some(node.id),
                unavailable_reason: None,
            });
        }
    }
    for relative in artifacts {
        items.push(artifact_evidence(relative, source_dir));
    }
    items.sort();
    items.dedup_by(|left: &mut EvidenceItem, right: &mut EvidenceItem| {
        left.role == right.role
            && left.uri == right.uri
            && left.blake3 == right.blake3
            && left.byte_offset == right.byte_offset
            && left.byte_length == right.byte_length
    });
    items
}

fn shell_argument(raw: &str) -> String {
    if !raw.is_empty()
        && !raw
            .chars()
            .any(|c: char| c.is_whitespace() || c == '"' || c == '\'')
    {
        return raw.to_string();
    }
    format!("\"{}\"", raw.replace('"', "\\\""))
}

fn reproduction_for(target: &Path, evidence: &[EvidenceItem]) -> Reproduction {
    let command: String = format!(
        "disrobe report {}",
        shell_argument(&target.display().to_string())
    );
    let recomputable: usize = evidence
        .iter()
        .filter(|item: &&EvidenceItem| item.hash_source == HashSource::RecomputedFromFile)
        .count();
    let unavailable: usize = evidence
        .iter()
        .filter(|item: &&EvidenceItem| item.hash_source == HashSource::Unavailable)
        .count();
    let mut steps: Vec<String> = vec![
        "hash the analysis target with blake3 and compare it with `input.blake3`".to_string(),
        format!(
            "hash the {recomputable} evidence {} marked `recomputed-from-file` and compare each digest with the recorded one",
            plural(recomputable, "entry", "entries")
        ),
        format!("read every `{CONTENT_URI_SCHEME}` evidence entry as the blake3 digest of an intermediate the chain held in memory; it names the artifact a byte range indexes"),
        format!("re-run `{command}`; text, json, markdown and html output is byte-identical, and sarif output differs only in `generated_at`"),
        "set SOURCE_DATE_EPOCH to a fixed value to make the sarif `generated_at` byte-identical too".to_string(),
    ];
    if unavailable > 0 {
        steps.push(format!(
            "{unavailable} evidence {} no digest; each one names why in `unavailable_reason`",
            plural(unavailable, "entry carries", "entries carry")
        ));
    }
    Reproduction { command, steps }
}

const fn plural(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 { one } else { many }
}

pub(crate) fn build_forensic(
    doc: &ChainDocument,
    recovery: &ChainRecoveryReport,
    out_dir: &Path,
) -> SingleReport {
    build_single(doc, recovery, Some(out_dir), out_dir)
}

fn build_single(
    doc: &ChainDocument,
    recovery: &ChainRecoveryReport,
    source_dir: Option<&Path>,
    target: &Path,
) -> SingleReport {
    let stage_nodes: Vec<Option<&NodeDoc>> = attribute_stages(doc, recovery);
    let mut all_artifacts: Vec<String> = Vec::new();
    let stages: Vec<StageView> = recovery
        .passes
        .iter()
        .enumerate()
        .map(
            |(idx, pass): (usize, &disrobe_core::chain::ChainPassRecovery)| {
                let node: Option<&NodeDoc> = stage_nodes.get(idx).copied().flatten();
                let artifacts: Vec<String> = node
                    .map(|n: &NodeDoc| n.artifacts.clone())
                    .unwrap_or_default();
                for a in &artifacts {
                    if !all_artifacts.contains(a) {
                        all_artifacts.push(a.clone());
                    }
                }
                let score: f64 = pass_score(pass);
                StageView {
                    index: idx + 1,
                    node_id: node.map_or(doc.root_node_id, |n: &NodeDoc| n.id),
                    pass: pass.name.clone(),
                    verdict: node.map_or_else(
                        || format!("{:?}", recovery.verdict),
                        |n: &NodeDoc| format!("{:?}", n.verdict),
                    ),
                    confidence: pass.confidence.as_str(),
                    recovery_score: score,
                    duration_ms: pass.duration_ms,
                    format_in: pass.format_in.clone(),
                    format_out: pass.format_out.clone(),
                    artifacts,
                }
            },
        )
        .collect();
    let (walls, failures): (Vec<WallView>, Vec<FailureView>) = collect_walls(doc, &stage_nodes);
    let (extracted, truncation): (Vec<String>, Option<String>) = walk_extracted(source_dir);
    let mut cited: Vec<String> = all_artifacts.clone();
    cited.extend(extracted);
    let evidence: Vec<EvidenceItem> = collect_evidence(doc, &stage_nodes, &cited, source_dir);
    let reproduction: Reproduction = reproduction_for(target, &evidence);
    let mut notes: Vec<String> = Vec::new();
    if let Some(note) = truncation {
        notes.push(note);
    }
    if recovery.passes.is_empty() {
        notes.push(
            "detect-only: no pass executed (format recognized but not transformed)".to_string(),
        );
    }
    if recovery.histogram.skeleton > 0 {
        notes.push(format!(
            "{} skeleton-tier stage(s): structure recovered, bodies incomplete",
            recovery.histogram.skeleton
        ));
    }
    SingleReport {
        kind: "single",
        schema: RECOVERY_REPORT_SCHEMA.to_string(),
        tool_version: doc.tool_version.clone(),
        source_dir: source_dir.map(|p: &Path| p.display().to_string()),
        input: InputIdentity {
            path: doc.input.path.clone(),
            size: doc.input.size,
            blake3: doc.input.blake3.clone(),
            detected: doc.input.detected.clone(),
            final_format: doc.final_format.clone(),
        },
        topology: format!("{:?}", doc.topology),
        verdict: format!("{:?}", doc.verdict),
        total_ms: recovery.total_ms,
        recovery_score: mean_score(recovery),
        tiers: TierTotals {
            exact: recovery.histogram.exact,
            semantic: recovery.histogram.semantic,
            partial: recovery.histogram.partial,
            skeleton: recovery.histogram.skeleton,
            total: recovery.histogram.total(),
        },
        stages,
        walls,
        failures,
        evidence,
        reproduction,
        artifacts: all_artifacts,
        notes,
    }
}

fn build_batch(manifest: &BatchManifest, source_dir: &Path) -> BatchReport {
    let files: Vec<BatchFileView> = manifest
        .entries
        .iter()
        .map(|e: &super::batch::ManifestEntry| BatchFileView {
            relative: e.relative.clone(),
            detected_format: e.detected_format.clone(),
            chain: e.chain.clone(),
            verdict: e.verdict.clone(),
            recovery_score: e.recovery_score,
            duration_ms: e.duration_ms,
            error: e.error.clone(),
        })
        .collect();
    let scored: Vec<f64> = manifest
        .entries
        .iter()
        .filter_map(|e: &super::batch::ManifestEntry| e.recovery_score)
        .collect();
    let mean_recovery_score: Option<f64> = if scored.is_empty() {
        None
    } else {
        Some(scored.iter().sum::<f64>() / scored.len() as f64)
    };
    BatchReport {
        schema: RECOVERY_REPORT_SCHEMA.to_string(),
        tool_version: manifest.tool_version.clone(),
        source_dir: source_dir.display().to_string(),
        root: manifest.root.clone(),
        chain: manifest.chain.clone(),
        processed: manifest.summary.processed,
        recovered: manifest.summary.recovered,
        detect_only: manifest.summary.detect_only,
        errors: manifest.summary.errors,
        mean_recovery_score,
        files,
    }
}

fn read_chain_doc(dir: &Path) -> miette::Result<ChainDocument> {
    let path: PathBuf = dir.join("chain.json");
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0351: cannot read {}: {e}", path.display()))?;
    serde_json::from_slice::<ChainDocument>(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0352: {} is not a valid chain.json: {e}",
            path.display()
        )
    })
}

fn read_recovery(dir: &Path) -> miette::Result<ChainRecoveryReport> {
    let path: PathBuf = dir.join("recovery.json");
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0353: cannot read {}: {e}", path.display()))?;
    serde_json::from_slice::<ChainRecoveryReport>(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0354: {} is not a valid recovery.json: {e}",
            path.display()
        )
    })
}

fn read_manifest(dir: &Path) -> miette::Result<BatchManifest> {
    let path: PathBuf = dir.join("manifest.json");
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0355: cannot read {}: {e}", path.display()))?;
    serde_json::from_slice::<BatchManifest>(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0356: {} is not a valid manifest.json: {e}",
            path.display()
        )
    })
}

fn derived_out_dir(input: &Path, base: Option<&Path>) -> PathBuf {
    let stem: &str = input
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .filter(|s: &&str| !s.is_empty())
        .unwrap_or("report");
    base.map_or_else(
        || PathBuf::from(format!("./out/{stem}-auto")),
        |root: &Path| root.join(format!("{stem}-auto")),
    )
}

fn derived_batch_dir(input: &Path, base: Option<&Path>) -> PathBuf {
    let stem: &str = input
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .filter(|s: &&str| !s.is_empty())
        .unwrap_or("batch");
    base.map_or_else(
        || PathBuf::from(format!("./out/{stem}-batch")),
        |root: &Path| root.join(format!("{stem}-batch")),
    )
}

fn resolve_document(target: &Path, base: Option<&Path>) -> miette::Result<ReportDocument> {
    if target.is_dir() {
        if target.join("manifest.json").is_file() {
            let manifest: BatchManifest = read_manifest(target)?;
            return Ok(ReportDocument::Batch(Box::new(build_batch(
                &manifest, target,
            ))));
        }
        if target.join("chain.json").is_file() {
            let doc: ChainDocument = read_chain_doc(target)?;
            let recovery: ChainRecoveryReport = read_recovery(target)?;
            return Ok(ReportDocument::Single(Box::new(build_single(
                &doc,
                &recovery,
                Some(target),
                target,
            ))));
        }
        let out_dir: PathBuf = derived_batch_dir(target, base);
        let opts: BatchOptions = BatchOptions {
            out_root: out_dir.clone(),
            chain_arg: "auto:8".to_string(),
            max_depth: None,
            include: Vec::new(),
            exclude: Vec::new(),
            jobs: 1,
            capture_stages: false,
            i_have_authorization: false,
        };
        let manifest: BatchManifest = batch::compute_manifest(target, &opts)?;
        return Ok(ReportDocument::Batch(Box::new(build_batch(
            &manifest, &out_dir,
        ))));
    }
    if target.is_file() {
        let out_dir: PathBuf = derived_out_dir(target, base);
        let bytes: Vec<u8> = std::fs::read(target).map_err(|e| {
            miette::miette!(
                "DR-CLI-0358: cannot read report input {}: {e}",
                target.display()
            )
        })?;
        let outcome: ChainOutcome = chain_v1::run_chain_to_dir(
            &target.display().to_string(),
            bytes,
            &out_dir,
            "auto:8",
            false,
            false,
        )?;
        return Ok(ReportDocument::Single(Box::new(build_single(
            &outcome.doc,
            &outcome.report,
            Some(&out_dir),
            target,
        ))));
    }
    Err(miette::miette!(
        "DR-CLI-0350: report target does not exist: {}",
        target.display()
    ))
}

fn render_text_single(r: &SingleReport, out: &mut String) {
    let _ = writeln!(out, "disrobe report  ({})", r.kind);
    let _ = writeln!(out, "  tool:        {}", r.tool_version);
    if let Some(src) = r.source_dir.as_deref() {
        let _ = writeln!(out, "  source:      {src}");
    }
    let _ = writeln!(
        out,
        "  input:       {} ({} bytes)",
        r.input.path.as_deref().unwrap_or("(unknown)"),
        r.input.size
    );
    let _ = writeln!(out, "  blake3:      {}", r.input.blake3);
    if !r.input.detected.is_empty() {
        let _ = writeln!(out, "  detected:    {}", r.input.detected.join(" -> "));
    }
    if let Some(ff) = r.input.final_format.as_deref() {
        let _ = writeln!(out, "  final:       {ff}");
    }
    let _ = writeln!(out, "  topology:    {}", r.topology);
    let _ = writeln!(out, "  verdict:     {}", r.verdict);
    let _ = writeln!(
        out,
        "  recovery:    {:.0}% ({})",
        r.recovery_score * 100.0,
        tier_label(r.recovery_score)
    );
    let _ = writeln!(
        out,
        "  tiers:       exact={} semantic={} partial={} skeleton={} (total {})",
        r.tiers.exact, r.tiers.semantic, r.tiers.partial, r.tiers.skeleton, r.tiers.total
    );
    let _ = writeln!(out, "  total_ms:    {}", r.total_ms);
    let _ = writeln!(out, "  stages:");
    for s in &r.stages {
        let _ = writeln!(
            out,
            "    {:>2}. {:<26} {:<10} {:>3.0}%  {}",
            s.index,
            s.pass,
            s.confidence,
            s.recovery_score * 100.0,
            s.duration_ms
                .map_or_else(|| "-".to_string(), |d: u128| format!("{d}ms"))
        );
    }
    if !r.walls.is_empty() {
        let _ = writeln!(out, "  walls:");
        for w in &r.walls {
            let _ = writeln!(
                out,
                "    [{}] node {}: {}",
                w.kind.label(),
                w.node_id,
                w.missing
            );
        }
    }
    if !r.failures.is_empty() {
        let _ = writeln!(out, "  failures:");
        for f in &r.failures {
            let _ = writeln!(
                out,
                "    node {} ({}): {}",
                f.node_id,
                f.pass.as_deref().unwrap_or(TERMINAL_PASS_NAME),
                f.message
            );
        }
    }
    if !r.artifacts.is_empty() {
        let _ = writeln!(out, "  artifacts:");
        for a in &r.artifacts {
            let _ = writeln!(out, "    - {a}");
        }
    }
    let _ = writeln!(out, "  evidence:");
    for e in &r.evidence {
        let _ = writeln!(
            out,
            "    {:<18} {} bytes {}+{} blake3={} ({})",
            e.role.label(),
            e.uri,
            e.byte_offset,
            e.byte_length
                .map_or_else(|| "?".to_string(), |l: u64| l.to_string()),
            e.blake3.as_deref().unwrap_or("-"),
            e.unavailable_reason
                .as_deref()
                .unwrap_or_else(|| e.hash_source.label())
        );
    }
    let _ = writeln!(out, "  reproduce:   {}", r.reproduction.command);
    for step in &r.reproduction.steps {
        let _ = writeln!(out, "    - {step}");
    }
    for note in &r.notes {
        let _ = writeln!(out, "  note:        {note}");
    }
}

fn render_text_batch(r: &BatchReport, out: &mut String) {
    let _ = writeln!(out, "disrobe report  (batch)");
    let _ = writeln!(out, "  tool:        {}", r.tool_version);
    let _ = writeln!(out, "  source:      {}", r.source_dir);
    let _ = writeln!(out, "  root:        {}", r.root);
    let _ = writeln!(out, "  chain:       {}", r.chain);
    let _ = writeln!(
        out,
        "  files:       {} processed, {} recovered, {} detect-only, {} errors",
        r.processed, r.recovered, r.detect_only, r.errors
    );
    if let Some(mean) = r.mean_recovery_score {
        let _ = writeln!(out, "  mean score:  {:.0}%", mean * 100.0);
    }
    let _ = writeln!(out, "  per-file:");
    for f in &r.files {
        let status: &str = if f.error.is_some() {
            "ERR "
        } else if f.chain.is_empty() {
            "scan"
        } else {
            "ok  "
        };
        let score: String = f
            .recovery_score
            .map_or_else(|| "-".to_string(), |s: f64| format!("{:.0}%", s * 100.0));
        let _ = writeln!(
            out,
            "    [{status}] {:<44} {:<5} {}",
            f.relative,
            score,
            f.error.as_deref().unwrap_or("")
        );
    }
}

fn render_markdown_single(r: &SingleReport, out: &mut String) {
    let _ = writeln!(out, "# disrobe report");
    let _ = writeln!(out);
    let _ = writeln!(out, "| field | value |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(
        out,
        "| input | `{}` |",
        r.input.path.as_deref().unwrap_or("(unknown)")
    );
    let _ = writeln!(out, "| size | {} bytes |", r.input.size);
    let _ = writeln!(out, "| blake3 | `{}` |", r.input.blake3);
    if let Some(ff) = r.input.final_format.as_deref() {
        let _ = writeln!(out, "| final format | {ff} |");
    }
    let _ = writeln!(out, "| topology | {} |", r.topology);
    let _ = writeln!(out, "| verdict | {} |", r.verdict);
    let _ = writeln!(
        out,
        "| recovery | {:.0}% ({}) |",
        r.recovery_score * 100.0,
        tier_label(r.recovery_score)
    );
    let _ = writeln!(out, "| total | {} ms |", r.total_ms);
    let _ = writeln!(out);
    let _ = writeln!(out, "## Stages");
    let _ = writeln!(out);
    let _ = writeln!(out, "| # | pass | confidence | score | duration |");
    let _ = writeln!(out, "|---:|---|---|---:|---:|");
    for s in &r.stages {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} | {:.0}% | {} |",
            s.index,
            s.pass,
            s.confidence,
            s.recovery_score * 100.0,
            s.duration_ms
                .map_or_else(|| "-".to_string(), |d: u128| format!("{d} ms"))
        );
    }
    if !r.walls.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Walls");
        let _ = writeln!(out);
        let _ = writeln!(out, "| kind | node | pass | missing input |");
        let _ = writeln!(out, "|---|---:|---|---|");
        for w in &r.walls {
            let _ = writeln!(
                out,
                "| {} | {} | `{}` | {} |",
                w.kind.label(),
                w.node_id,
                w.pass.as_deref().unwrap_or(TERMINAL_PASS_NAME),
                w.missing
            );
        }
    }
    if !r.failures.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Failures");
        let _ = writeln!(out);
        let _ = writeln!(out, "| node | pass | message |");
        let _ = writeln!(out, "|---:|---|---|");
        for f in &r.failures {
            let _ = writeln!(
                out,
                "| {} | `{}` | {} |",
                f.node_id,
                f.pass.as_deref().unwrap_or(TERMINAL_PASS_NAME),
                f.message
            );
        }
    }
    if !r.artifacts.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Recovered artifacts");
        let _ = writeln!(out);
        for a in &r.artifacts {
            let _ = writeln!(out, "- `{a}`");
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Evidence");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| role | artifact | byte offset | byte length | blake3 | digest source |"
    );
    let _ = writeln!(out, "|---|---|---:|---:|---|---|");
    for e in &r.evidence {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} | {} | `{}` | {} |",
            e.role.label(),
            e.uri,
            e.byte_offset,
            e.byte_length
                .map_or_else(|| "-".to_string(), |l: u64| l.to_string()),
            e.blake3.as_deref().unwrap_or("-"),
            e.unavailable_reason
                .as_deref()
                .unwrap_or_else(|| e.hash_source.label())
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Reproduction");
    let _ = writeln!(out);
    let _ = writeln!(out, "```");
    let _ = writeln!(out, "{}", r.reproduction.command);
    let _ = writeln!(out, "```");
    let _ = writeln!(out);
    for step in &r.reproduction.steps {
        let _ = writeln!(out, "- {step}");
    }
    if !r.notes.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Notes");
        let _ = writeln!(out);
        for note in &r.notes {
            let _ = writeln!(out, "- {note}");
        }
    }
}

fn render_markdown_batch(r: &BatchReport, out: &mut String) {
    let _ = writeln!(out, "# disrobe report (batch)");
    let _ = writeln!(out);
    let _ = writeln!(out, "- root: `{}`", r.root);
    let _ = writeln!(out, "- chain: `{}`", r.chain);
    let _ = writeln!(
        out,
        "- {} processed, {} recovered, {} detect-only, {} errors",
        r.processed, r.recovered, r.detect_only, r.errors
    );
    if let Some(mean) = r.mean_recovery_score {
        let _ = writeln!(out, "- mean recovery score: {:.0}%", mean * 100.0);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "| file | format | score | status |");
    let _ = writeln!(out, "|---|---|---:|---|");
    for f in &r.files {
        let status: &str = if f.error.is_some() {
            "error"
        } else if f.chain.is_empty() {
            "detect-only"
        } else {
            "recovered"
        };
        let score: String = f
            .recovery_score
            .map_or_else(|| "-".to_string(), |s: f64| format!("{:.0}%", s * 100.0));
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            f.relative,
            f.detected_format.as_deref().unwrap_or("-"),
            score,
            status
        );
    }
}

pub(crate) fn run(
    target: PathBuf,
    format: ReportFormat,
    fmt: OutputFormat,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    let document: ReportDocument = resolve_document(&target, out.as_deref())?;
    let effective: ReportFormat = if fmt.is_machine() && format != ReportFormat::Sarif {
        ReportFormat::Json
    } else {
        format
    };
    match effective {
        ReportFormat::Sarif => {
            let log: String = super::report_forensic::render_sarif(&document)?;
            println!("{log}");
            Ok(())
        }
        ReportFormat::Json => {
            let s: String = serde_json::to_string_pretty(&document)
                .map_err(|e| miette::miette!("DR-CLI-0357: report serialize: {e}"))?;
            println!("{s}");
            Ok(())
        }
        ReportFormat::Text => {
            let mut buf: String = String::new();
            match &document {
                ReportDocument::Single(s) => render_text_single(s, &mut buf),
                ReportDocument::Batch(b) => render_text_batch(b, &mut buf),
            }
            print!("{buf}");
            Ok(())
        }
        ReportFormat::Markdown => {
            let mut buf: String = String::new();
            match &document {
                ReportDocument::Single(s) => render_markdown_single(s, &mut buf),
                ReportDocument::Batch(b) => render_markdown_batch(b, &mut buf),
            }
            print!("{buf}");
            Ok(())
        }
        ReportFormat::Html => {
            let html: String = match &document {
                ReportDocument::Single(s) => {
                    let enrichment: super::report_html::Enrichment =
                        super::report_html::enrich_single(s);
                    super::report_html::render_single_html(s, &enrichment)
                }
                ReportDocument::Batch(b) => super::report_html::render_batch_html(b),
            };
            print!("{html}");
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) const fn tier_totals_for_test(
    exact: u32,
    semantic: u32,
    partial: u32,
    skeleton: u32,
) -> TierTotals {
    TierTotals {
        exact,
        semantic,
        partial,
        skeleton,
        total: exact + semantic + partial + skeleton,
    }
}

#[cfg(test)]
pub(crate) fn batch_report_for_test() -> BatchReport {
    BatchReport {
        schema: RECOVERY_REPORT_SCHEMA.to_string(),
        tool_version: "0.9.0".to_string(),
        source_dir: "out/samples-batch".to_string(),
        root: "samples".to_string(),
        chain: "auto:8".to_string(),
        processed: 2,
        recovered: 1,
        detect_only: 0,
        errors: 1,
        mean_recovery_score: Some(0.67),
        files: vec![
            BatchFileView {
                relative: "a.pyc".to_string(),
                detected_format: Some("Python".to_string()),
                chain: vec!["py.decompile".to_string()],
                verdict: Some("Complete".to_string()),
                recovery_score: Some(0.67),
                duration_ms: 5,
                error: None,
            },
            BatchFileView {
                relative: "bad".to_string(),
                detected_format: None,
                chain: Vec::new(),
                verdict: None,
                recovery_score: None,
                duration_ms: 1,
                error: Some("read failed".to_string()),
            },
        ],
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::panic
)]
mod tests {
    use super::*;
    use disrobe_core::scratch::ScratchDir;

    fn tmp_dir(stem: &str) -> ScratchDir {
        let purpose: String = format!("disrobe-report-{stem}");
        ScratchDir::create(&purpose).expect("create scratch directory")
    }

    const CHAIN_JSON: &str = r#"{
      "schema": "disrobe.chain/v1",
      "tool_version": "0.9.0",
      "input": { "path": "app.pyc", "blake3": "abcd", "size": 128, "detected": ["pyc-3.11"] },
      "spec": { "raw": "auto:8", "kind": "auto", "cap": 8 },
      "topology": "linear",
      "root_node_id": 0,
      "nodes": [
        { "id": 0, "parent_id": null, "depth": 0, "branch_id": "root",
          "pass": null, "format_tag_in": null, "input_blake3": "abcd", "input_size": 128,
          "output_kind": null, "output_blake3": null, "output_size": null,
          "duration_ms": null, "detector_picks": [], "artifacts": [], "metadata": {},
          "verdict": "ok", "error": null },
        { "id": 1, "parent_id": 0, "depth": 1, "branch_id": "root",
          "pass": "py.decompile", "format_tag_in": "pyc-3.11", "input_blake3": "abcd", "input_size": 128,
          "output_kind": { "kind": "source", "language": "Python", "formatted": true },
          "output_blake3": "ef01", "output_size": 64,
          "duration_ms": 7, "detector_picks": [], "artifacts": ["app.py"], "metadata": {},
          "verdict": "complete", "error": null }
      ],
      "verdict": "complete",
      "final_format": "Python",
      "stats": { "layers": 1, "branches": 1, "total_ms": 7,
        "max_branch_depth": 1, "detector_calls": 1, "rejected_passes": 0 }
    }"#;

    const RECOVERY_JSON: &str = r#"{
      "schema": "disrobe.recovery/v1",
      "tool_version": "0.9.0",
      "input": { "path": "app.pyc", "blake3": "abcd", "size": 128 },
      "passes": [
        { "name": "py.decompile", "status": "recovered", "confidence": "semantic",
          "duration_ms": 7, "format_in": "pyc-3.11", "format_out": "Python" }
      ],
      "histogram": { "exact": 0, "semantic": 1, "partial": 0, "skeleton": 0 },
      "total_ms": 7,
      "verdict": "complete"
    }"#;

    fn seed_single_dir(stem: &str) -> (ScratchDir, PathBuf) {
        let scratch: ScratchDir = tmp_dir(stem);
        let dir: PathBuf = scratch.path().to_path_buf();
        std::fs::write(dir.join("chain.json"), CHAIN_JSON).expect("w chain");
        std::fs::write(dir.join("recovery.json"), RECOVERY_JSON).expect("w recovery");
        (scratch, dir)
    }

    const TREE_CHAIN_JSON: &str = r#"{
      "schema": "disrobe.chain/v1",
      "tool_version": "0.9.0",
      "input": { "path": "bundle.zip", "blake3": "0000", "size": 256, "detected": ["zip"] },
      "spec": { "raw": "auto:8", "kind": "auto", "cap": 8 },
      "topology": "tree",
      "root_node_id": 0,
      "nodes": [
        { "id": 0, "parent_id": null, "depth": 0, "branch_id": "root",
          "pass": null, "format_tag_in": null, "input_blake3": "0000", "input_size": 256,
          "output_kind": null, "output_blake3": null, "output_size": null,
          "duration_ms": null, "detector_picks": [], "artifacts": [], "metadata": {},
          "verdict": "fan-out", "error": null },
        { "id": 1, "parent_id": 0, "depth": 1, "branch_id": "a",
          "pass": "py.decompile", "format_tag_in": "pyc-3.11", "input_blake3": "1111", "input_size": 64,
          "output_kind": { "kind": "source", "language": "Python", "formatted": true },
          "output_blake3": "aaaa", "output_size": 32,
          "duration_ms": 3, "detector_picks": [], "artifacts": ["left.py"], "metadata": {},
          "verdict": "complete", "error": null },
        { "id": 2, "parent_id": 0, "depth": 1, "branch_id": "b",
          "pass": "py.decompile", "format_tag_in": "pyc-3.11", "input_blake3": "2222", "input_size": 96,
          "output_kind": { "kind": "source", "language": "Python", "formatted": true },
          "output_blake3": "bbbb", "output_size": 48,
          "duration_ms": 4, "detector_picks": [], "artifacts": ["right.py"], "metadata": {},
          "verdict": "complete", "error": null }
      ],
      "verdict": "complete",
      "final_format": "Python",
      "stats": { "layers": 2, "branches": 2, "total_ms": 7,
        "max_branch_depth": 1, "detector_calls": 2, "rejected_passes": 0 }
    }"#;

    const TREE_RECOVERY_JSON: &str = r#"{
      "schema": "disrobe.recovery/v1",
      "tool_version": "0.9.0",
      "input": { "path": "bundle.zip", "blake3": "0000", "size": 256 },
      "passes": [
        { "name": "py.decompile", "status": "recovered", "confidence": "semantic",
          "duration_ms": 3, "format_in": "pyc-3.11", "format_out": "Python" },
        { "name": "py.decompile", "status": "recovered", "confidence": "semantic",
          "duration_ms": 4, "format_in": "pyc-3.11", "format_out": "Python" }
      ],
      "histogram": { "exact": 0, "semantic": 2, "partial": 0, "skeleton": 0 },
      "total_ms": 7,
      "verdict": "complete"
    }"#;

    const STALLED_CHAIN_JSON: &str = r#"{
      "schema": "disrobe.chain/v1",
      "tool_version": "0.9.0",
      "input": { "path": "opaque.bin", "blake3": "dead", "size": 512, "detected": [] },
      "spec": { "raw": "auto:8", "kind": "auto", "cap": 8 },
      "topology": "linear",
      "root_node_id": 0,
      "nodes": [
        { "id": 0, "parent_id": null, "depth": 0, "branch_id": "root",
          "pass": null, "format_tag_in": null, "input_blake3": "dead", "input_size": 512,
          "output_kind": null, "output_blake3": null, "output_size": null,
          "duration_ms": null, "detector_picks": [], "artifacts": [], "metadata": {},
          "verdict": "stalled", "error": null }
      ],
      "verdict": "stalled",
      "final_format": null,
      "stats": { "layers": 0, "branches": 1, "total_ms": 1,
        "max_branch_depth": 0, "detector_calls": 3, "rejected_passes": 3 }
    }"#;

    const STALLED_RECOVERY_JSON: &str = r#"{
      "schema": "disrobe.recovery/v1",
      "tool_version": "0.9.0",
      "input": { "path": "opaque.bin", "blake3": "dead", "size": 512 },
      "passes": [],
      "histogram": { "exact": 0, "semantic": 0, "partial": 0, "skeleton": 0 },
      "total_ms": 1,
      "verdict": "stalled"
    }"#;

    const DRY_RUN_CHAIN_JSON: &str = r#"{
      "schema": "disrobe.chain/v1",
      "tool_version": "0.9.0",
      "input": { "path": "app.pyc", "blake3": "abcd", "size": 128, "detected": ["pyc-3.11"] },
      "spec": { "raw": "auto:8", "kind": "auto", "cap": 8 },
      "topology": "linear",
      "root_node_id": 0,
      "nodes": [
        { "id": 0, "parent_id": null, "depth": 0, "branch_id": "root",
          "pass": null, "format_tag_in": null, "input_blake3": "abcd", "input_size": 128,
          "output_kind": null, "output_blake3": null, "output_size": null,
          "duration_ms": null, "detector_picks": [], "artifacts": [], "metadata": {},
          "verdict": "ok", "error": null },
        { "id": 1, "parent_id": 0, "depth": 1, "branch_id": "root",
          "pass": "py.decompile", "format_tag_in": "pyc-3.11", "input_blake3": "abcd", "input_size": 128,
          "output_kind": null, "output_blake3": null, "output_size": null,
          "duration_ms": null, "detector_picks": [], "artifacts": ["app.py"], "metadata": {},
          "verdict": "dry-run", "error": null }
      ],
      "verdict": "dry-run",
      "final_format": null,
      "stats": { "layers": 1, "branches": 1, "total_ms": 0,
        "max_branch_depth": 1, "detector_calls": 1, "rejected_passes": 0 }
    }"#;

    const DRY_RUN_RECOVERY_JSON: &str = r#"{
      "schema": "disrobe.recovery/v1",
      "tool_version": "0.9.0",
      "input": { "path": "app.pyc", "blake3": "abcd", "size": 128 },
      "passes": [
        { "name": "py.decompile", "status": "skipped", "confidence": "skeleton",
          "duration_ms": null, "format_in": "pyc-3.11", "format_out": null }
      ],
      "histogram": { "exact": 0, "semantic": 0, "partial": 0, "skeleton": 1 },
      "total_ms": 0,
      "verdict": "dry-run"
    }"#;

    fn seed_dir(stem: &str, chain: &str, recovery: &str) -> (ScratchDir, PathBuf) {
        let scratch: ScratchDir = tmp_dir(stem);
        let dir: PathBuf = scratch.path().to_path_buf();
        std::fs::write(dir.join("chain.json"), chain).expect("w chain");
        std::fs::write(dir.join("recovery.json"), recovery).expect("w recovery");
        (scratch, dir)
    }

    fn single_of(dir: &Path) -> Box<SingleReport> {
        match resolve_document(dir, None).expect("resolve") {
            ReportDocument::Single(s) => s,
            ReportDocument::Batch(_) => panic!("expected single report"),
        }
    }

    #[test]
    fn a_repeated_pass_name_in_a_tree_attributes_each_stage_to_its_own_node() {
        let (_scratch, dir): (ScratchDir, PathBuf) =
            seed_dir("tree", TREE_CHAIN_JSON, TREE_RECOVERY_JSON);
        let report: Box<SingleReport> = single_of(&dir);
        assert_eq!(report.stages.len(), 2);
        assert_eq!(report.stages[0].node_id, 1);
        assert_eq!(report.stages[1].node_id, 2);
        assert_eq!(
            report.stages[0].artifacts,
            vec!["left.py".to_string()],
            "stage 1 must carry node 1 artifacts, not the first name match"
        );
        assert_eq!(
            report.stages[1].artifacts,
            vec!["right.py".to_string()],
            "stage 2 must carry node 2 artifacts, not the first name match"
        );
        let stage_inputs: Vec<&EvidenceItem> = report
            .evidence
            .iter()
            .filter(|e: &&EvidenceItem| e.role == EvidenceRole::StageInput)
            .collect();
        assert_eq!(stage_inputs.len(), 2, "{stage_inputs:?}");
        assert!(
            stage_inputs
                .iter()
                .any(|e: &&EvidenceItem| e.blake3.as_deref() == Some("1111"))
        );
        assert!(
            stage_inputs
                .iter()
                .any(|e: &&EvidenceItem| e.blake3.as_deref() == Some("2222"))
        );
    }

    #[test]
    fn a_detect_only_run_reports_the_wall_instead_of_an_empty_success() {
        let (_scratch, dir): (ScratchDir, PathBuf) =
            seed_dir("stalled", STALLED_CHAIN_JSON, STALLED_RECOVERY_JSON);
        let report: Box<SingleReport> = single_of(&dir);
        assert!(report.stages.is_empty());
        assert!(report.failures.is_empty(), "a wall is not a failure");
        assert_eq!(report.walls.len(), 1, "{:?}", report.walls);
        assert_eq!(report.walls[0].kind, WallKind::NoPassAccepted);
        assert!(
            report.walls[0].missing.contains("dead"),
            "the wall must name the artifact it could not advance: {}",
            report.walls[0].missing
        );
        assert!(
            report.walls[0].missing.contains("512"),
            "the wall must name the size of the artifact it could not advance: {}",
            report.walls[0].missing
        );
        assert!(
            (report.recovery_score - 0.0).abs() < f64::EPSILON,
            "a detect-only run has no scored stage"
        );
    }

    #[test]
    fn a_dry_run_wall_names_the_pass_that_never_executed() {
        let (_scratch, dir): (ScratchDir, PathBuf) =
            seed_dir("dry-run", DRY_RUN_CHAIN_JSON, DRY_RUN_RECOVERY_JSON);
        let report: Box<SingleReport> = single_of(&dir);
        assert_eq!(report.walls.len(), 1, "{:?}", report.walls);
        assert_eq!(report.walls[0].kind, WallKind::NotExecuted);
        assert_eq!(report.walls[0].stage_index, Some(1));
        assert!(report.walls[0].missing.contains("py.decompile"));
        let missing_artifact: &EvidenceItem = report
            .evidence
            .iter()
            .find(|e: &&EvidenceItem| e.role == EvidenceRole::RecoveredArtifact)
            .expect("a dry run still cites the artifact it would have written");
        assert_eq!(missing_artifact.hash_source, HashSource::Unavailable);
        assert!(
            missing_artifact
                .unavailable_reason
                .as_deref()
                .is_some_and(|r: &str| r.contains("app.py")),
            "{missing_artifact:?}"
        );
    }

    #[test]
    fn a_recovered_artifact_is_cited_with_a_digest_computed_from_the_file_on_disk() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("evidence");
        std::fs::write(dir.join("app.py"), b"print('hello')\n").expect("w artifact");
        let report: Box<SingleReport> = single_of(&dir);
        let cited: &EvidenceItem = report
            .evidence
            .iter()
            .find(|e: &&EvidenceItem| e.role == EvidenceRole::RecoveredArtifact)
            .expect("the recovered artifact must be cited");
        assert_eq!(cited.hash_source, HashSource::RecomputedFromFile);
        assert_eq!(cited.byte_offset, 0);
        assert_eq!(cited.byte_length, Some(15));
        assert_eq!(
            cited.blake3.as_deref(),
            Some(blake3::hash(b"print('hello')\n").to_hex().as_str()),
            "the cited digest must be blake3 over the exact file bytes"
        );
    }

    #[test]
    fn the_reproduction_block_names_the_command_that_rebuilds_the_report() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("repro");
        let report: Box<SingleReport> = single_of(&dir);
        assert!(
            report.reproduction.command.starts_with("disrobe report "),
            "{}",
            report.reproduction.command
        );
        assert!(
            report
                .reproduction
                .steps
                .iter()
                .any(|s: &String| s.contains("SOURCE_DATE_EPOCH")),
            "{:?}",
            report.reproduction.steps
        );
    }

    #[test]
    fn tier_label_thresholds() {
        assert_eq!(tier_label(1.0), "exact");
        assert_eq!(tier_label(0.67), "semantic");
        assert_eq!(tier_label(0.5), "partial");
        assert_eq!(tier_label(0.1), "skeleton");
    }

    #[test]
    fn resolves_single_out_dir() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("single");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve single");
        match doc {
            ReportDocument::Single(s) => {
                assert_eq!(s.input.path.as_deref(), Some("app.pyc"));
                assert_eq!(s.input.size, 128);
                assert_eq!(s.stages.len(), 1);
                assert_eq!(s.stages[0].pass, "py.decompile");
                assert_eq!(s.stages[0].confidence, "semantic");
                assert!((s.recovery_score - 0.6666).abs() < 0.01);
                assert!(s.artifacts.contains(&"app.py".to_string()));
            }
            ReportDocument::Batch(_) => panic!("expected single report"),
        }
    }

    #[test]
    fn text_render_contains_key_fields() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("text");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve");
        let ReportDocument::Single(s) = doc else {
            panic!("single");
        };
        let mut buf: String = String::new();
        render_text_single(&s, &mut buf);
        assert!(buf.contains("py.decompile"), "got: {buf}");
        assert!(buf.contains("blake3:"), "got: {buf}");
        assert!(buf.contains("app.py"), "artifact inventory missing: {buf}");
    }

    #[test]
    fn markdown_render_is_tabular() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("md");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve");
        let ReportDocument::Single(s) = doc else {
            panic!("single");
        };
        let mut buf: String = String::new();
        render_markdown_single(&s, &mut buf);
        assert!(buf.starts_with("# disrobe report"), "got: {buf}");
        assert!(buf.contains("## Stages"), "got: {buf}");
        assert!(buf.contains("| `py.decompile` |"), "got: {buf}");
    }

    #[test]
    fn json_document_round_trips_as_value() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("json");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve");
        let value: serde_json::Value = serde_json::to_value(&doc).expect("to value");
        assert_eq!(value["report_kind"], serde_json::json!("single"));
        assert_eq!(value["input"]["size"], serde_json::json!(128));
        assert_eq!(
            value["stages"][0]["pass"],
            serde_json::json!("py.decompile")
        );
    }

    #[test]
    fn resolves_batch_out_dir() {
        let scratch: ScratchDir = tmp_dir("batch");
        let dir: PathBuf = scratch.path().to_path_buf();
        let manifest: &str = r#"{
          "schema": "disrobe.batch.manifest/v1",
          "tool_version": "0.9.0",
          "root": "samples",
          "out_root": "out/samples-batch",
          "chain": "auto:8",
          "jobs": 1,
          "summary": { "processed": 2, "recovered": 1, "detect_only": 0, "errors": 1 },
          "entries": [
            { "input": "samples/a.pyc", "relative": "a.pyc", "size": 64,
              "detected_format": "Python", "chain": ["py.decompile"], "verdict": "Complete",
              "recovery_score": 0.67, "output_dir": "out/samples-batch/a.pyc",
              "duration_ms": 5, "error": null },
            { "input": "samples/bad", "relative": "bad", "size": 0,
              "detected_format": null, "chain": [], "verdict": null,
              "recovery_score": null, "output_dir": null, "duration_ms": 1,
              "error": "read failed" }
          ]
        }"#;
        std::fs::write(dir.join("manifest.json"), manifest).expect("w manifest");
        let doc: ReportDocument = resolve_document(&dir, None).expect("resolve batch");
        let ReportDocument::Batch(b) = doc else {
            panic!("expected batch report");
        };
        assert_eq!(b.processed, 2);
        assert_eq!(b.errors, 1);
        assert_eq!(b.files.len(), 2);
        assert_eq!(b.mean_recovery_score, Some(0.67));
        let mut buf: String = String::new();
        render_markdown_batch(&b, &mut buf);
        assert!(buf.contains("# disrobe report (batch)"), "got: {buf}");
        assert!(buf.contains("error"), "errored file must show; got: {buf}");
    }

    #[test]
    fn a_truncated_run_document_is_a_typed_error_not_a_panic() {
        let (_scratch, dir): (ScratchDir, PathBuf) = seed_single_dir("truncated-recovery");
        std::fs::write(dir.join("recovery.json"), &RECOVERY_JSON[..40]).expect("truncate recovery");
        let err: miette::Report = resolve_document(&dir, None).expect_err("must error");
        assert!(
            format!("{err}").contains("DR-CLI-0354"),
            "a truncated recovery.json must stay a typed error: {err}"
        );

        let (_second, other): (ScratchDir, PathBuf) = seed_single_dir("truncated-chain");
        std::fs::write(other.join("chain.json"), &CHAIN_JSON[..64]).expect("truncate chain");
        let chain_err: miette::Report = resolve_document(&other, None).expect_err("must error");
        assert!(
            format!("{chain_err}").contains("DR-CLI-0352"),
            "a truncated chain.json must stay a typed error: {chain_err}"
        );

        let (_third, missing): (ScratchDir, PathBuf) = seed_single_dir("absent-recovery");
        std::fs::remove_file(missing.join("recovery.json")).expect("remove recovery");
        let absent: miette::Report = resolve_document(&missing, None).expect_err("must error");
        assert!(
            format!("{absent}").contains("DR-CLI-0353"),
            "an absent recovery.json must stay a typed error: {absent}"
        );
    }

    #[test]
    fn missing_target_is_error() {
        let scratch: ScratchDir = tmp_dir("missing");
        let missing: PathBuf = scratch.path().join("nope");
        let err: miette::Report = resolve_document(&missing, None).expect_err("must error");
        assert!(format!("{err}").contains("DR-CLI-0350"));
    }

    #[test]
    fn without_a_chosen_root_the_derived_run_lands_under_the_working_directory() {
        let single: PathBuf = derived_out_dir(Path::new("sample.bin"), None);
        assert_eq!(single, PathBuf::from("./out/sample-auto"));
        let batch: PathBuf = derived_batch_dir(Path::new("corpus"), None);
        assert_eq!(batch, PathBuf::from("./out/corpus-batch"));
    }

    #[test]
    fn a_chosen_root_takes_the_derived_run_out_of_the_working_directory() {
        let scratch: ScratchDir = tmp_dir("chosen-root");
        let root: PathBuf = scratch.path().to_path_buf();
        let single: PathBuf = derived_out_dir(Path::new("sample.bin"), Some(&root));
        assert_eq!(single, root.join("sample-auto"));
        assert!(
            !single.starts_with("./out"),
            "a chosen root must not still write beside the working directory: {}",
            single.display()
        );
        let batch: PathBuf = derived_batch_dir(Path::new("corpus"), Some(&root));
        assert_eq!(batch, root.join("corpus-batch"));
    }
}
