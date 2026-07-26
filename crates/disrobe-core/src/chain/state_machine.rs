use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::detection::{DetectContext, OutputKind, PassRunOutcome};
use super::registry::{DetectorPick, PassRegistry, PickOutcome, SelectionPolicy};
use super::spec::{ChainSpec, SpecCursor};

pub type NodeId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Verdict {
    Ok,
    Complete { formats: Vec<String> },
    FanOut { count: u32 },
    FanOutPartial { ok: u32, total: u32 },
    Stalled,
    Cycle,
    CapReached,
    Extracted,
    Error { message: String },
    DryRun,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: NodeId,
    pub parent_id: Option<NodeId>,
    pub depth: u8,
    pub branch_id: String,
    pub pass_id: Option<String>,
    pub format_tag_in: Option<String>,
    pub input_blake3: [u8; 32],
    pub input_size: u64,
    pub output_kind: Option<OutputKind>,
    pub output_blake3: Option<[u8; 32]>,
    pub output_size: Option<u64>,
    pub output_bytes: Option<Vec<u8>>,
    pub duration: Option<Duration>,
    pub picks: Vec<DetectorPick>,
    pub artifacts: Vec<String>,
    pub metadata: BTreeMap<String, String>,
    pub verdict: Verdict,
}

pub const DEFAULT_MAX_CUMULATIVE_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub max_parallel_branches: u32,
    pub capture_stage_bytes: bool,
    pub persist_children: bool,
    pub stream_extracted: bool,
    pub max_cumulative_output_bytes: u64,
    pub selection_policy: SelectionPolicy,
    pub i_have_authorization: bool,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            max_parallel_branches: 8,
            capture_stage_bytes: false,
            persist_children: false,
            stream_extracted: false,
            max_cumulative_output_bytes: DEFAULT_MAX_CUMULATIVE_OUTPUT_BYTES,
            selection_policy: SelectionPolicy::default(),
            i_have_authorization: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtractedArtifact {
    pub node_id: NodeId,
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WorkItem {
    pub parent: NodeId,
    pub bytes: Vec<u8>,
    pub depth: u8,
    pub branch_id: String,
    pub history: BTreeSet<[u8; 32]>,
    pub container_lineage: BTreeSet<String>,
    pub spec_cursor: SpecCursor,
    pub path_hint: Option<String>,
    pub parent_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChainPlan {
    pub nodes: Vec<Node>,
    pub root_id: NodeId,
    pub verdict: Verdict,
    pub final_format: Option<String>,
    pub total: Duration,
    pub detector_calls: u32,
    pub rejected_passes: u32,
    pub has_multiple_branches: bool,
    pub extracted: Vec<ExtractedArtifact>,
}

impl ChainPlan {
    #[inline]
    #[must_use]
    pub fn root(&self) -> &Node {
        &self.nodes[self.root_id as usize]
    }

    #[must_use]
    pub fn max_branch_depth(&self) -> u8 {
        self.nodes.iter().map(|n: &Node| n.depth).max().unwrap_or(0)
    }

    #[must_use]
    pub fn branch_count(&self) -> u32 {
        let mut s: BTreeSet<&str> = BTreeSet::new();
        for n in &self.nodes {
            s.insert(n.branch_id.as_str());
        }
        u32::try_from(s.len()).unwrap_or(u32::MAX)
    }
}

pub trait PassRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: Vec<u8>,
        config: &ChainConfig,
        path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String>;
}

#[derive(Debug)]
pub struct ChainDriver<'r, R: PassRunner> {
    pub registry: &'r PassRegistry,
    pub runner: &'r R,
    pub config: ChainConfig,
}

impl<'r, R: PassRunner> ChainDriver<'r, R> {
    #[must_use]
    pub const fn new(registry: &'r PassRegistry, runner: &'r R, config: ChainConfig) -> Self {
        Self {
            registry,
            runner,
            config,
        }
    }

    #[must_use]
    pub fn run(&self, seed: Vec<u8>, spec: &ChainSpec, path_hint: Option<String>) -> ChainPlan {
        let mut noop = |_: &ExtractedArtifact| {};
        self.run_with_sink(seed, spec, path_hint, &mut noop)
    }

    #[must_use]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    pub fn run_with_sink(
        &self,
        seed: Vec<u8>,
        spec: &ChainSpec,
        path_hint: Option<String>,
        sink: &mut dyn FnMut(&ExtractedArtifact),
    ) -> ChainPlan {
        let started: Instant = Instant::now();
        let mut nodes: Vec<Node> = Vec::new();
        let mut extracted: Vec<ExtractedArtifact> = Vec::new();
        let mut detector_calls: u32 = 0;
        let mut rejected: u32 = 0;
        let mut branch_seq: u64 = 0;
        let mut seen_inputs: BTreeSet<[u8; 32]> = BTreeSet::new();

        let seed_hash: [u8; 32] = blake3_of(&seed);
        let seed_size: u64 = seed.len() as u64;
        let root_branch: String = next_branch_id(&mut branch_seq);
        let root: Node = Node {
            id: 0,
            parent_id: None,
            depth: 0,
            branch_id: root_branch.clone(),
            pass_id: None,
            format_tag_in: None,
            input_blake3: seed_hash,
            input_size: seed_size,
            output_kind: None,
            output_blake3: None,
            output_size: None,
            output_bytes: None,
            duration: None,
            picks: Vec::new(),
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
            verdict: Verdict::Ok,
        };
        nodes.push(root);

        if spec.is_plan_only() {
            let plan: ChainPlan = ChainPlan {
                nodes,
                root_id: 0,
                verdict: Verdict::DryRun,
                final_format: None,
                total: started.elapsed(),
                detector_calls: 0,
                rejected_passes: 0,
                has_multiple_branches: false,
                extracted: Vec::new(),
            };
            return plan;
        }

        let mut queue: VecDeque<WorkItem> = VecDeque::new();
        queue.push_back(WorkItem {
            parent: 0,
            bytes: seed,
            depth: 1,
            branch_id: root_branch,
            history: {
                let mut h: BTreeSet<[u8; 32]> = BTreeSet::new();
                h.insert(seed_hash);
                h
            },
            container_lineage: BTreeSet::new(),
            spec_cursor: ChainSpec::cursor_for_root(),
            path_hint,
            parent_hint: None,
        });

        let mut cumulative_output_bytes: u64 = 0;
        let mut output_budget_exceeded: bool = false;

        while let Some(item) = queue.pop_front() {
            if item.depth > spec.cap() {
                push_terminal_layer(
                    &mut nodes,
                    item.parent,
                    item.depth,
                    item.branch_id.clone(),
                    blake3_of(&item.bytes),
                    item.bytes.len() as u64,
                    Verdict::CapReached,
                );
                continue;
            }
            if output_budget_exceeded {
                push_terminal_layer(
                    &mut nodes,
                    item.parent,
                    item.depth,
                    item.branch_id.clone(),
                    blake3_of(&item.bytes),
                    item.bytes.len() as u64,
                    Verdict::CapReached,
                );
                continue;
            }
            let in_hash: [u8; 32] = blake3_of(&item.bytes);
            let in_size: u64 = item.bytes.len() as u64;
            if !seen_inputs.insert(in_hash) {
                push_terminal_layer(
                    &mut nodes,
                    item.parent,
                    item.depth,
                    item.branch_id.clone(),
                    in_hash,
                    in_size,
                    Verdict::Cycle,
                );
                continue;
            }
            let ctx: DetectContext<'_> = DetectContext {
                bytes: &item.bytes,
                path_hint: item.path_hint.as_deref(),
                parent_hint: item.parent_hint.as_deref(),
                depth: item.depth,
            };
            let pick_opt: Option<DetectorPick> = if let Some(tok) = spec.pin_at(item.spec_cursor) {
                self.registry.get(tok.pass_id.as_str()).and_then(
                    |pass: &dyn super::detector::Pass| {
                        detector_calls += 1;
                        pass.detector()
                            .detect(&ctx)
                            .map(|v| DetectorPick { pass, verdict: v })
                    },
                )
            } else {
                let cands: Vec<super::detection::DetectVerdict> = self.registry.run_all(&ctx);
                detector_calls += u32::try_from(cands.len()).unwrap_or(u32::MAX);
                let outcome: PickOutcome = self
                    .registry
                    .pick_with_policy(cands, &self.config.selection_policy);
                rejected =
                    rejected.saturating_add(u32::try_from(outcome.dropped).unwrap_or(u32::MAX));
                outcome.pick
            };
            let Some(pick): Option<DetectorPick> = pick_opt else {
                push_terminal_layer(
                    &mut nodes,
                    item.parent,
                    item.depth,
                    item.branch_id.clone(),
                    in_hash,
                    in_size,
                    Verdict::Stalled,
                );
                continue;
            };
            let layer_id: NodeId = u32::try_from(nodes.len()).unwrap_or(u32::MAX);
            let format_tag_in: String = pick.verdict.format_tag.to_string();
            let input_bytes: Vec<u8> = item.bytes;
            let pass_run: Result<PassRunOutcome, String> =
                self.runner
                    .run(&pick, input_bytes, &self.config, item.path_hint.as_deref());
            match pass_run {
                Err(msg) => {
                    nodes.push(Node {
                        verdict: Verdict::Error { message: msg },
                        ..pass_node_base(
                            layer_id,
                            item.parent,
                            item.depth,
                            item.branch_id.clone(),
                            in_hash,
                            in_size,
                            format_tag_in,
                            pick,
                        )
                    });
                }
                Ok(outcome) => {
                    let outcome_bytes_len: u64 = outcome.output_bytes.len() as u64
                        + outcome
                            .children
                            .iter()
                            .map(|c: &Vec<u8>| c.len() as u64)
                            .sum::<u64>();
                    cumulative_output_bytes =
                        cumulative_output_bytes.saturating_add(outcome_bytes_len);
                    if cumulative_output_bytes > self.config.max_cumulative_output_bytes {
                        output_budget_exceeded = true;
                    }
                    match outcome.kind.clone() {
                        OutputKind::Source {
                            language,
                            formatted: _,
                        } => {
                            let out_hash: [u8; 32] = blake3_of(&outcome.output_bytes);
                            let out_size: u64 = outcome.output_bytes.len() as u64;
                            let captured: Option<Vec<u8>> = if self.config.capture_stage_bytes {
                                Some(outcome.output_bytes.clone())
                            } else {
                                None
                            };
                            let no_further_progress: bool = item.history.contains(&out_hash);
                            let further_pick: Option<DetectorPick> = if no_further_progress {
                                None
                            } else {
                                let peek_ctx: DetectContext<'_> = DetectContext {
                                    bytes: &outcome.output_bytes,
                                    path_hint: item.path_hint.as_deref(),
                                    parent_hint: Some(language.label()),
                                    depth: item.depth.saturating_add(1),
                                };
                                let peek_cands: Vec<super::detection::DetectVerdict> =
                                    self.registry.run_all(&peek_ctx);
                                detector_calls +=
                                    u32::try_from(peek_cands.len()).unwrap_or(u32::MAX);
                                let peek_outcome: PickOutcome = self
                                    .registry
                                    .pick_with_policy(peek_cands, &self.config.selection_policy);
                                rejected = rejected.saturating_add(
                                    u32::try_from(peek_outcome.dropped).unwrap_or(u32::MAX),
                                );
                                peek_outcome.pick
                            };
                            if further_pick.is_some() {
                                nodes.push(Node {
                                    output_kind: Some(outcome.kind),
                                    output_blake3: Some(out_hash),
                                    output_size: Some(out_size),
                                    output_bytes: captured,
                                    duration: Some(outcome.duration),
                                    metadata: outcome.metadata,
                                    verdict: Verdict::Ok,
                                    ..pass_node_base(
                                        layer_id,
                                        item.parent,
                                        item.depth,
                                        item.branch_id.clone(),
                                        in_hash,
                                        in_size,
                                        format_tag_in.clone(),
                                        pick,
                                    )
                                });
                                let mut next_history: BTreeSet<[u8; 32]> = item.history.clone();
                                next_history.insert(out_hash);
                                let mut next_container_lineage: BTreeSet<String> =
                                    item.container_lineage.clone();
                                next_container_lineage.insert(format_tag_in);
                                queue.push_back(WorkItem {
                                    parent: layer_id,
                                    bytes: outcome.output_bytes,
                                    depth: item.depth.saturating_add(1),
                                    branch_id: item.branch_id.clone(),
                                    history: next_history,
                                    container_lineage: next_container_lineage,
                                    spec_cursor: item.spec_cursor.advance(),
                                    path_hint: item.path_hint.clone(),
                                    parent_hint: Some(language.label().to_string()),
                                });
                            } else {
                                nodes.push(Node {
                                    output_kind: Some(outcome.kind),
                                    output_blake3: Some(out_hash),
                                    output_size: Some(out_size),
                                    output_bytes: captured,
                                    duration: Some(outcome.duration),
                                    metadata: outcome.metadata,
                                    verdict: Verdict::Complete {
                                        formats: vec![language.label().to_string()],
                                    },
                                    ..pass_node_base(
                                        layer_id,
                                        item.parent,
                                        item.depth,
                                        item.branch_id.clone(),
                                        in_hash,
                                        in_size,
                                        format_tag_in,
                                        pick,
                                    )
                                });
                            }
                        }
                        OutputKind::Bytes {
                            format_tag,
                            family: _,
                        } => {
                            if outcome.output_bytes.is_empty() {
                                nodes.push(Node {
                                    output_kind: Some(outcome.kind),
                                    output_size: Some(0),
                                    duration: Some(outcome.duration),
                                    metadata: outcome.metadata,
                                    verdict: Verdict::Stalled,
                                    ..pass_node_base(
                                        layer_id,
                                        item.parent,
                                        item.depth,
                                        item.branch_id.clone(),
                                        in_hash,
                                        in_size,
                                        format_tag_in,
                                        pick,
                                    )
                                });
                                continue;
                            }
                            let out_hash: [u8; 32] = blake3_of(&outcome.output_bytes);
                            if item.history.contains(&out_hash) {
                                nodes.push(Node {
                                    output_kind: Some(outcome.kind),
                                    output_blake3: Some(out_hash),
                                    output_size: Some(outcome.output_bytes.len() as u64),
                                    duration: Some(outcome.duration),
                                    metadata: outcome.metadata,
                                    verdict: Verdict::Cycle,
                                    ..pass_node_base(
                                        layer_id,
                                        item.parent,
                                        item.depth,
                                        item.branch_id.clone(),
                                        in_hash,
                                        in_size,
                                        format_tag_in,
                                        pick,
                                    )
                                });
                                continue;
                            }
                            let out_size: u64 = outcome.output_bytes.len() as u64;
                            let kind_clone: OutputKind = outcome.kind.clone();
                            let captured: Option<Vec<u8>> = if self.config.capture_stage_bytes {
                                Some(outcome.output_bytes.clone())
                            } else {
                                None
                            };
                            nodes.push(Node {
                                output_kind: Some(kind_clone),
                                output_blake3: Some(out_hash),
                                output_size: Some(out_size),
                                output_bytes: captured,
                                duration: Some(outcome.duration),
                                metadata: outcome.metadata,
                                verdict: Verdict::Ok,
                                ..pass_node_base(
                                    layer_id,
                                    item.parent,
                                    item.depth,
                                    item.branch_id.clone(),
                                    in_hash,
                                    in_size,
                                    format_tag_in.clone(),
                                    pick,
                                )
                            });
                            let mut next_history: BTreeSet<[u8; 32]> = item.history.clone();
                            next_history.insert(out_hash);
                            let mut next_container_lineage: BTreeSet<String> =
                                item.container_lineage.clone();
                            next_container_lineage.insert(format_tag_in);
                            queue.push_back(WorkItem {
                                parent: layer_id,
                                bytes: outcome.output_bytes,
                                depth: item.depth.saturating_add(1),
                                branch_id: item.branch_id.clone(),
                                history: next_history,
                                container_lineage: next_container_lineage,
                                spec_cursor: item.spec_cursor.advance(),
                                path_hint: item.path_hint.clone(),
                                parent_hint: Some(format_tag.to_string()),
                            });
                        }
                        OutputKind::Mixed { children } => {
                            let child_count: u32 =
                                u32::try_from(children.len()).unwrap_or(u32::MAX);
                            let mut child_bytes: Vec<Vec<u8>> = outcome.children;
                            nodes.push(Node {
                                output_kind: Some(outcome.kind),
                                duration: Some(outcome.duration),
                                metadata: outcome.metadata,
                                verdict: Verdict::FanOut { count: child_count },
                                ..pass_node_base(
                                    layer_id,
                                    item.parent,
                                    item.depth,
                                    item.branch_id.clone(),
                                    in_hash,
                                    in_size,
                                    format_tag_in.clone(),
                                    pick,
                                )
                            });
                            for ch in children {
                                let child_branch: String = next_branch_id(&mut branch_seq);
                                let next_bytes: Vec<u8> = if let Some(bytes) =
                                    child_bytes.get_mut(ch.artifact_index as usize)
                                {
                                    std::mem::take(bytes)
                                } else {
                                    push_terminal_layer(
                                        &mut nodes,
                                        layer_id,
                                        item.depth.saturating_add(1),
                                        child_branch,
                                        blake3_of(&[]),
                                        0,
                                        Verdict::Error {
                                            message: format!(
                                                "missing mixed child artifact {}",
                                                ch.artifact_index
                                            ),
                                        },
                                    );
                                    continue;
                                };
                                if next_bytes.is_empty() {
                                    push_terminal_layer(
                                        &mut nodes,
                                        layer_id,
                                        item.depth.saturating_add(1),
                                        child_branch,
                                        blake3_of(&next_bytes),
                                        0,
                                        Verdict::Stalled,
                                    );
                                    continue;
                                }
                                let child_hash: [u8; 32] = blake3_of(&next_bytes);
                                let child_len: u64 = next_bytes.len() as u64;
                                if ch.is_terminal() {
                                    if self.config.persist_children {
                                        let artifact: ExtractedArtifact = ExtractedArtifact {
                                            node_id: layer_id,
                                            relative_path: ch.relative_path.clone(),
                                            bytes: next_bytes,
                                        };
                                        sink(&artifact);
                                        if !self.config.stream_extracted {
                                            extracted.push(artifact);
                                        }
                                    }
                                    push_terminal_layer(
                                        &mut nodes,
                                        layer_id,
                                        item.depth.saturating_add(1),
                                        child_branch,
                                        child_hash,
                                        child_len,
                                        Verdict::Extracted,
                                    );
                                    continue;
                                }
                                let mut child_history: BTreeSet<[u8; 32]> = item.history.clone();
                                child_history.insert(child_hash);
                                if self.config.persist_children {
                                    let artifact: ExtractedArtifact = ExtractedArtifact {
                                        node_id: layer_id,
                                        relative_path: ch.relative_path.clone(),
                                        bytes: next_bytes.clone(),
                                    };
                                    sink(&artifact);
                                    if !self.config.stream_extracted {
                                        extracted.push(artifact);
                                    }
                                }
                                let mut child_container_lineage: BTreeSet<String> =
                                    item.container_lineage.clone();
                                child_container_lineage.insert(format_tag_in.clone());
                                queue.push_back(WorkItem {
                                    parent: layer_id,
                                    bytes: next_bytes,
                                    depth: item.depth.saturating_add(1),
                                    branch_id: child_branch,
                                    history: child_history,
                                    container_lineage: child_container_lineage,
                                    spec_cursor: item.spec_cursor.advance(),
                                    path_hint: Some(ch.relative_path),
                                    parent_hint: ch.hint,
                                });
                            }
                        }
                    }
                }
            }
        }
        let has_multiple_branches: bool = {
            let mut s: BTreeSet<&str> = BTreeSet::new();
            for n in &nodes {
                s.insert(n.branch_id.as_str());
            }
            s.len() > 1
        };
        let final_verdict: Verdict = aggregate_verdict(&nodes);
        let final_format: Option<String> = nodes.iter().find_map(|n: &Node| match &n.verdict {
            Verdict::Complete { formats } => formats.first().cloned(),
            _ => None,
        });
        ChainPlan {
            nodes,
            root_id: 0,
            verdict: final_verdict,
            final_format,
            total: started.elapsed(),
            detector_calls,
            rejected_passes: rejected,
            has_multiple_branches,
            extracted,
        }
    }
}

fn aggregate_verdict(nodes: &[Node]) -> Verdict {
    let leaves: Vec<&Node> = collect_leaves(nodes);
    if leaves.is_empty() {
        return Verdict::Stalled;
    }
    let mut total: u32 = 0;
    let mut complete: u32 = 0;
    let mut cycle: bool = false;
    let mut cap: bool = false;
    let mut error: bool = false;
    let mut stalled: bool = false;
    let mut formats: Vec<String> = Vec::new();
    for leaf in &leaves {
        total = total.saturating_add(1);
        match &leaf.verdict {
            Verdict::Complete {
                formats: leaf_formats,
            } => {
                complete = complete.saturating_add(1);
                for f in leaf_formats {
                    if !formats.contains(f) {
                        formats.push(f.clone());
                    }
                }
            }
            Verdict::Cycle => cycle = true,
            Verdict::CapReached => cap = true,
            Verdict::Error { .. } => error = true,
            Verdict::Stalled => stalled = true,
            _ => {}
        }
    }
    if complete == total {
        Verdict::Complete { formats }
    } else if complete > 0 {
        Verdict::FanOutPartial {
            ok: complete,
            total,
        }
    } else if cap {
        Verdict::CapReached
    } else if cycle {
        Verdict::Cycle
    } else if error {
        Verdict::Error {
            message: "all branches errored".to_string(),
        }
    } else if stalled {
        Verdict::Stalled
    } else {
        Verdict::Ok
    }
}

fn collect_leaves(nodes: &[Node]) -> Vec<&Node> {
    let mut has_child: BTreeSet<NodeId> = BTreeSet::new();
    for n in nodes {
        if let Some(p) = n.parent_id {
            has_child.insert(p);
        }
    }
    nodes
        .iter()
        .filter(|n: &&Node| !has_child.contains(&n.id))
        .collect()
}

fn pass_node_base(
    layer_id: NodeId,
    parent: NodeId,
    depth: u8,
    branch_id: String,
    input_blake3: [u8; 32],
    input_size: u64,
    format_tag_in: String,
    pick: DetectorPick,
) -> Node {
    let pass_id: String = pick.verdict.pass_id.to_string();
    Node {
        id: layer_id,
        parent_id: Some(parent),
        depth,
        branch_id,
        pass_id: Some(pass_id),
        format_tag_in: Some(format_tag_in),
        input_blake3,
        input_size,
        output_kind: None,
        output_blake3: None,
        output_size: None,
        output_bytes: None,
        duration: None,
        picks: vec![pick],
        artifacts: Vec::new(),
        metadata: BTreeMap::new(),
        verdict: Verdict::Ok,
    }
}

fn push_terminal_layer(
    nodes: &mut Vec<Node>,
    parent: NodeId,
    depth: u8,
    branch_id: String,
    input_hash: [u8; 32],
    input_size: u64,
    verdict: Verdict,
) {
    let id: NodeId = u32::try_from(nodes.len()).unwrap_or(u32::MAX);
    nodes.push(Node {
        id,
        parent_id: Some(parent),
        depth,
        branch_id,
        pass_id: None,
        format_tag_in: None,
        input_blake3: input_hash,
        input_size,
        output_kind: None,
        output_blake3: None,
        output_size: None,
        output_bytes: None,
        duration: None,
        picks: Vec::new(),
        artifacts: Vec::new(),
        metadata: BTreeMap::new(),
        verdict,
    });
}

fn next_branch_id(seq: &mut u64) -> String {
    let s: String = encode_branch_id(*seq);
    *seq = seq.saturating_add(1);
    s
}

fn encode_branch_id(mut n: u64) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity(4);
    loop {
        let rem: u8 = (n % 26) as u8;
        buf.push(b'a' + rem);
        n /= 26;
        if n == 0 {
            break;
        }
        n -= 1;
    }
    buf.reverse();
    String::from_utf8(buf).unwrap_or_else(|_| "a".to_string())
}

fn blake3_of(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::artifact::Artifact;
    use crate::chain::detection::{ChildHandle, ConfidenceBand, DetectVerdict};
    use crate::chain::detector::{Detector, Pass};
    use crate::pass::PassId;
    use crate::provenance::Language;
    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    #[derive(Debug)]
    struct StubPass {
        id: &'static str,
    }

    const STUB_ALREADY_CLEAN_SOURCE: &[u8] = b"src";

    #[derive(Debug)]
    struct StubDetector {
        id: &'static str,
        family: &'static str,
        confidence: f32,
        specificity: u16,
    }
    impl Detector for StubDetector {
        fn id(&self) -> PassId {
            self.id
        }
        fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
            if ctx.bytes == STUB_ALREADY_CLEAN_SOURCE {
                return None;
            }
            Some(DetectVerdict::new(
                self.id,
                "tag",
                self.family,
                self.confidence,
                self.specificity,
                vec![],
                String::new(),
            ))
        }
    }

    static DET_A: StubDetector = StubDetector {
        id: "stub.a",
        family: super::super::FAMILY_OBFUSCATOR_WRAPPER,
        confidence: 0.95,
        specificity: 10,
    };
    static PASS_A: StubPass = StubPass { id: "stub.a" };
    impl Pass for StubPass {
        fn id(&self) -> PassId {
            self.id
        }
        fn detector(&self) -> &'static dyn Detector {
            &DET_A
        }
        fn output_kind(&self, _o: &Artifact) -> OutputKind {
            OutputKind::Source {
                language: Language::Python,
                formatted: true,
            }
        }
        fn run(&self, a: &Artifact) -> crate::error::Result<Artifact> {
            Ok(a.clone())
        }
    }

    type RunnerFn = Box<dyn Fn(u32, &[u8]) -> Result<PassRunOutcome, String> + Send + Sync>;

    struct CountingRunner {
        calls: AtomicU32,
        produce: RunnerFn,
    }
    impl std::fmt::Debug for CountingRunner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CountingRunner")
                .field("calls", &self.calls)
                .finish_non_exhaustive()
        }
    }
    impl PassRunner for CountingRunner {
        fn run(
            &self,
            _pick: &DetectorPick,
            bytes: Vec<u8>,
            _cfg: &ChainConfig,
            _path_hint: Option<&str>,
        ) -> Result<PassRunOutcome, String> {
            let n: u32 = self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            (self.produce)(n, &bytes)
        }
    }

    fn registry_with_a() -> PassRegistry {
        let mut r: PassRegistry = PassRegistry::new();
        r.register(&PASS_A);
        r
    }

    #[test]
    fn empty_registry_yields_stalled() {
        let r: PassRegistry = PassRegistry::new();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_, _| Err("never called".to_string())),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let plan: ChainPlan = d.run(b"abc".to_vec(), &spec, None);
        assert!(matches!(plan.verdict, Verdict::Stalled));
        assert_eq!(plan.detector_calls, 0);
    }

    fn fanout_then_terminal() -> RunnerFn {
        Box::new(|n: u32, _bytes: &[u8]| {
            if n == 0 {
                Ok(PassRunOutcome {
                    output_bytes: Vec::new(),
                    kind: OutputKind::Mixed {
                        children: vec![
                            ChildHandle {
                                artifact_index: 0,
                                relative_path: "main.dll".to_string(),
                                hint: None,
                            },
                            ChildHandle {
                                artifact_index: 1,
                                relative_path: "sub/_wmi.pyd".to_string(),
                                hint: None,
                            },
                        ],
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: vec![b"MZ-main-payload".to_vec(), b"MZ-wmi-payload".to_vec()],
                })
            } else {
                Ok(PassRunOutcome {
                    output_bytes: b"recovered-source".to_vec(),
                    kind: OutputKind::Source {
                        language: Language::Python,
                        formatted: true,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }
        })
    }

    #[test]
    fn fanout_children_are_persisted_when_enabled() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: fanout_then_terminal(),
        };
        let cfg: ChainConfig = ChainConfig {
            persist_children: true,
            ..ChainConfig::default()
        };
        let d: ChainDriver<'_, CountingRunner> = ChainDriver::new(&r, &runner, cfg);
        let plan: ChainPlan = d.run(b"root-onefile".to_vec(), &ChainSpec::Auto { cap: 8 }, None);
        assert_eq!(
            plan.extracted.len(),
            2,
            "both fan-out children must be captured for on-disk persistence"
        );
        let by_path: BTreeMap<&str, &[u8]> = plan
            .extracted
            .iter()
            .map(|e: &ExtractedArtifact| (e.relative_path.as_str(), e.bytes.as_slice()))
            .collect();
        assert_eq!(
            by_path.get("main.dll").copied(),
            Some(b"MZ-main-payload".as_slice())
        );
        assert_eq!(
            by_path.get("sub/_wmi.pyd").copied(),
            Some(b"MZ-wmi-payload".as_slice())
        );
    }

    fn fanout_terminal_only() -> RunnerFn {
        Box::new(|_n: u32, _bytes: &[u8]| {
            Ok(PassRunOutcome {
                output_bytes: Vec::new(),
                kind: OutputKind::Mixed {
                    children: vec![ChildHandle {
                        artifact_index: 0,
                        relative_path: "extracted/big_app.dll".to_string(),
                        hint: Some(super::super::detection::TERMINAL_HINT.to_string()),
                    }],
                },
                duration: Duration::from_millis(1),
                metadata: BTreeMap::new(),
                children: vec![b"MZ-terminal-payload".to_vec()],
            })
        })
    }

    #[test]
    fn terminal_child_streamed_not_rechained() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: fanout_terminal_only(),
        };
        let cfg: ChainConfig = ChainConfig {
            persist_children: true,
            stream_extracted: true,
            ..ChainConfig::default()
        };
        let d: ChainDriver<'_, CountingRunner> = ChainDriver::new(&r, &runner, cfg);
        let mut streamed: Vec<(String, Vec<u8>)> = Vec::new();
        let mut sink = |a: &ExtractedArtifact| {
            streamed.push((a.relative_path.clone(), a.bytes.clone()));
        };
        let plan: ChainPlan = d.run_with_sink(
            b"root-onefile".to_vec(),
            &ChainSpec::Auto { cap: 8 },
            None,
            &mut sink,
        );
        assert_eq!(
            runner.calls.load(AtomicOrdering::SeqCst),
            1,
            "the terminal child must NOT be re-fed into a second pass run"
        );
        assert_eq!(
            streamed.len(),
            1,
            "the terminal child must be streamed to the sink"
        );
        assert_eq!(streamed[0].0, "extracted/big_app.dll");
        assert!(
            plan.extracted.is_empty(),
            "stream_extracted must not retain bytes in the plan"
        );
        assert!(
            plan.nodes
                .iter()
                .any(|n: &Node| matches!(n.verdict, Verdict::Extracted)),
            "terminal child node must carry the Extracted verdict"
        );
    }

    #[test]
    fn fanout_children_not_captured_when_disabled() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: fanout_then_terminal(),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let plan: ChainPlan = d.run(b"root-onefile".to_vec(), &ChainSpec::Auto { cap: 8 }, None);
        assert!(
            plan.extracted.is_empty(),
            "default config must not retain child bytes (memory bound for non-disk callers)"
        );
    }

    #[test]
    fn cycle_on_self_aborts() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_, bytes: &[u8]| {
                Ok(PassRunOutcome {
                    output_bytes: bytes.to_vec(),
                    kind: OutputKind::Bytes {
                        format_tag: "x",
                        family: super::super::FAMILY_OBFUSCATOR_WRAPPER,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let any_cycle: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::Cycle));
        assert!(any_cycle, "expected at least one Cycle verdict in plan");
    }

    #[test]
    fn cap_reached_with_fresh_bytes() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|n: u32, _b: &[u8]| {
                Ok(PassRunOutcome {
                    output_bytes: format!("fresh-{n}").into_bytes(),
                    kind: OutputKind::Bytes {
                        format_tag: "x",
                        family: super::super::FAMILY_OBFUSCATOR_WRAPPER,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Auto { cap: 3 };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let any_cap: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::CapReached));
        assert!(any_cap, "expected CapReached verdict");
    }

    #[test]
    fn complete_on_source_output() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_n, _b| {
                Ok(PassRunOutcome {
                    output_bytes: b"print('hi')".to_vec(),
                    kind: OutputKind::Source {
                        language: Language::Python,
                        formatted: true,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let any_complete: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::Complete { .. }));
        assert!(any_complete);
        assert_eq!(plan.final_format.as_deref(), Some("Python"));
    }

    const WRAPPED_LAYER_PREFIX: &[u8] = b"WRAP:";

    fn strip_one_wrap_layer(bytes: &[u8]) -> Vec<u8> {
        bytes
            .strip_prefix(WRAPPED_LAYER_PREFIX)
            .unwrap_or(bytes)
            .to_vec()
    }

    #[test]
    fn source_output_that_still_matches_a_further_pass_stays_non_terminal_and_the_chain_progresses_to_real_completion()
     {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_n: u32, bytes: &[u8]| {
                Ok(PassRunOutcome {
                    output_bytes: strip_one_wrap_layer(bytes),
                    kind: OutputKind::Source {
                        language: Language::Python,
                        formatted: true,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let cfg: ChainConfig = ChainConfig {
            capture_stage_bytes: true,
            ..ChainConfig::default()
        };
        let d: ChainDriver<'_, CountingRunner> = ChainDriver::new(&r, &runner, cfg);
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let mut seed: Vec<u8> = WRAPPED_LAYER_PREFIX.to_vec();
        seed.extend_from_slice(WRAPPED_LAYER_PREFIX);
        seed.extend_from_slice(STUB_ALREADY_CLEAN_SOURCE);
        let plan: ChainPlan = d.run(seed, &spec, None);

        assert_eq!(
            runner.calls.load(AtomicOrdering::SeqCst),
            2,
            "a still-wrapped recovered source must genuinely drive a second real pass \
             invocation, not merely flip a verdict label"
        );
        let first_hop: &Node = plan
            .nodes
            .iter()
            .find(|n: &&Node| n.parent_id == Some(0))
            .expect("root must have a direct child for the first pass run");
        assert_eq!(
            first_hop.verdict,
            Verdict::Ok,
            "recovered source that still matches a further pass must not be marked terminal"
        );
        assert!(
            matches!(first_hop.output_kind, Some(OutputKind::Source { .. })),
            "provenance must be preserved: the non-terminal hop is still Source-shaped"
        );
        let second_hop: &Node = plan
            .nodes
            .iter()
            .find(|n: &&Node| n.parent_id == Some(first_hop.id))
            .expect("a real child work item must have been enqueued and processed");
        assert_eq!(second_hop.pass_id.as_deref(), Some("stub.a"));
        assert_eq!(
            second_hop.verdict,
            Verdict::Complete {
                formats: vec!["Python".to_string()]
            },
            "the chain must reach a genuine terminal state once nothing further matches"
        );
        assert_eq!(
            second_hop.output_bytes.as_deref(),
            Some(STUB_ALREADY_CLEAN_SOURCE),
            "tracing to actual completion: the final recovered bytes must be the fully \
             unwrapped source, not a placeholder"
        );
        assert_eq!(plan.final_format.as_deref(), Some("Python"));
    }

    #[test]
    fn source_output_with_no_further_pass_stays_byte_for_byte_complete() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_n, _b| {
                Ok(PassRunOutcome {
                    output_bytes: STUB_ALREADY_CLEAN_SOURCE.to_vec(),
                    kind: OutputKind::Source {
                        language: Language::Python,
                        formatted: true,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let cfg: ChainConfig = ChainConfig {
            capture_stage_bytes: true,
            ..ChainConfig::default()
        };
        let d: ChainDriver<'_, CountingRunner> = ChainDriver::new(&r, &runner, cfg);
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);

        assert_eq!(
            runner.calls.load(AtomicOrdering::SeqCst),
            1,
            "no pass claims the already-clean recovered source, so exactly one invocation \
             must occur; a second, wasted invocation would mean the 99% terminal case \
             regressed"
        );
        let leaf: &Node = plan
            .nodes
            .iter()
            .find(|n: &&Node| n.parent_id == Some(0))
            .expect("root must have exactly one direct child");
        assert_eq!(
            leaf.verdict,
            Verdict::Complete {
                formats: vec!["Python".to_string()]
            },
            "the old unconditional-terminal verdict shape must be preserved byte-for-byte \
             when no further pass claims the recovered source"
        );
        assert!(matches!(leaf.output_kind, Some(OutputKind::Source { .. })));
        assert_eq!(
            leaf.output_bytes.as_deref(),
            Some(STUB_ALREADY_CLEAN_SOURCE)
        );
        assert!(
            !plan
                .nodes
                .iter()
                .any(|n: &Node| n.parent_id == Some(leaf.id)),
            "a genuinely terminal source must never enqueue a child work item"
        );
        assert_eq!(plan.final_format.as_deref(), Some("Python"));
    }

    #[test]
    fn source_chain_of_sources_terminates_via_recursion_budget_not_an_infinite_loop() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|n: u32, _b: &[u8]| {
                Ok(PassRunOutcome {
                    output_bytes: format!("gen-{n}").into_bytes(),
                    kind: OutputKind::Source {
                        language: Language::Python,
                        formatted: true,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Auto { cap: 5 };
        let started: Instant = Instant::now();
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "a source pass whose output is always re-claimed by a further source-shaped \
             pass must still terminate quickly, took {elapsed:?}"
        );
        let calls: u32 = runner.calls.load(AtomicOrdering::SeqCst);
        assert_eq!(
            calls, 5,
            "the depth cap of 5 must halt this ever-distinct, always-re-detected source \
             chain after exactly 5 real pass invocations, got {calls}"
        );
        let any_cap: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::CapReached));
        assert!(
            any_cap,
            "expected the existing depth-cap machinery to terminal-layer the runaway \
             source-of-sources chain as CapReached"
        );
        let any_complete: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::Complete { .. }));
        assert!(
            !any_complete,
            "an ever-distinct, always-re-detected source chain must never fabricate a \
             Complete verdict; it must cap out instead"
        );
    }

    fn stub_leaf(id: NodeId, branch_id: &str, verdict: Verdict) -> Node {
        Node {
            id,
            parent_id: Some(0),
            depth: 1,
            branch_id: branch_id.to_string(),
            pass_id: Some("stub.a".to_string()),
            format_tag_in: Some("tag".to_string()),
            input_blake3: [0u8; 32],
            input_size: 16,
            output_kind: None,
            output_blake3: None,
            output_size: None,
            output_bytes: None,
            duration: None,
            picks: Vec::new(),
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
            verdict,
        }
    }

    #[test]
    fn aggregate_verdict_carries_every_leaf_real_format() {
        let root: Node = Node {
            id: 0,
            parent_id: None,
            depth: 0,
            branch_id: "a".to_string(),
            pass_id: None,
            format_tag_in: None,
            input_blake3: [0u8; 32],
            input_size: 16,
            output_kind: None,
            output_blake3: None,
            output_size: None,
            output_bytes: None,
            duration: None,
            picks: Vec::new(),
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
            verdict: Verdict::FanOut { count: 2 },
        };
        let leaf_a: Node = stub_leaf(
            1,
            "b",
            Verdict::Complete {
                formats: vec!["Python".to_string()],
            },
        );
        let leaf_b: Node = stub_leaf(
            2,
            "c",
            Verdict::Complete {
                formats: vec!["Manifest".to_string()],
            },
        );
        let nodes: Vec<Node> = vec![root, leaf_a, leaf_b];
        let aggregated: Verdict = aggregate_verdict(&nodes);
        let Verdict::Complete { formats } = aggregated else {
            panic!("expected an aggregate Complete verdict, got {aggregated:?}");
        };
        assert_eq!(
            formats,
            vec!["Python".to_string(), "Manifest".to_string()],
            "aggregate must carry each completed leaf's real format, not an empty placeholder"
        );
    }

    #[test]
    fn fan_out_creates_branches() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|n: u32, _b| {
                if n == 0 {
                    Ok(PassRunOutcome {
                        output_bytes: Vec::new(),
                        kind: OutputKind::Mixed {
                            children: vec![
                                ChildHandle {
                                    artifact_index: 0,
                                    relative_path: "a.pyc".to_string(),
                                    hint: Some("interpreter-bytecode".to_string()),
                                },
                                ChildHandle {
                                    artifact_index: 1,
                                    relative_path: "b.pyc".to_string(),
                                    hint: Some("interpreter-bytecode".to_string()),
                                },
                            ],
                        },
                        duration: Duration::from_millis(1),
                        metadata: BTreeMap::new(),
                        children: vec![b"child-a-bytes".to_vec(), b"child-b-bytes".to_vec()],
                    })
                } else {
                    Ok(PassRunOutcome {
                        output_bytes: STUB_ALREADY_CLEAN_SOURCE.to_vec(),
                        kind: OutputKind::Source {
                            language: Language::Python,
                            formatted: true,
                        },
                        duration: Duration::from_millis(1),
                        metadata: BTreeMap::new(),
                        children: Vec::new(),
                    })
                }
            }),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let fan: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::FanOut { count: 2 }));
        assert!(fan);
        assert!(plan.has_multiple_branches);
        assert!(plan.branch_count() >= 3);
        let fan_node_id: NodeId = plan
            .nodes
            .iter()
            .find(|n: &&Node| matches!(n.verdict, Verdict::FanOut { .. }))
            .expect("a fan-out node")
            .id;
        let refed_children: Vec<&Node> = plan
            .nodes
            .iter()
            .filter(|n: &&Node| n.parent_id == Some(fan_node_id))
            .collect();
        assert_eq!(
            refed_children.len(),
            2,
            "both mixed children must be re-fed with their real bytes, not dropped"
        );
        let expected_len: u64 = b"child-a-bytes".len() as u64;
        let real_byte_children: usize = refed_children
            .iter()
            .filter(|n: &&&Node| n.input_size == expected_len)
            .count();
        assert_eq!(
            real_byte_children, 2,
            "each re-fed child node must carry the real child byte length, not an empty placeholder"
        );
        let complete_children: usize = refed_children
            .iter()
            .filter(|n: &&&Node| matches!(n.verdict, Verdict::Complete { .. }))
            .count();
        assert_eq!(
            complete_children, 2,
            "each re-fed child must advance to a Complete source terminal"
        );
    }

    #[test]
    fn fan_out_missing_child_artifact_errors() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_n: u32, _b| {
                Ok(PassRunOutcome {
                    output_bytes: Vec::new(),
                    kind: OutputKind::Mixed {
                        children: vec![ChildHandle {
                            artifact_index: 7,
                            relative_path: "missing.bin".to_string(),
                            hint: None,
                        }],
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let plan: ChainPlan = d.run(b"seed".to_vec(), &ChainSpec::Auto { cap: 8 }, None);
        assert!(plan.nodes.iter().any(|n: &Node| {
            matches!(
                &n.verdict,
                Verdict::Error { message } if message == "missing mixed child artifact 7"
            )
        }));
    }

    #[test]
    fn explicit_chain_pin_order_respected() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_n, _b| {
                Ok(PassRunOutcome {
                    output_bytes: b"final".to_vec(),
                    kind: OutputKind::Source {
                        language: Language::Python,
                        formatted: true,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Explicit {
            passes: vec![super::super::spec::PassToken::new("stub.a")],
        };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let used_a: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| n.pass_id.as_deref() == Some("stub.a"));
        assert!(used_a);
    }

    #[test]
    fn plan_only_emits_dry_run_no_calls() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_n, _b| Err("never".to_string())),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::PlanOnly { cap: 8 };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        assert!(matches!(plan.verdict, Verdict::DryRun));
        assert_eq!(runner.calls.load(AtomicOrdering::SeqCst), 0);
        let _ = ConfidenceBand::High;
    }

    #[test]
    fn branch_id_encoding() {
        assert_eq!(encode_branch_id(0), "a");
        assert_eq!(encode_branch_id(1), "b");
        assert_eq!(encode_branch_id(25), "z");
        assert_eq!(encode_branch_id(26), "aa");
        assert_eq!(encode_branch_id(27), "ab");
        assert_eq!(encode_branch_id(51), "az");
        assert_eq!(encode_branch_id(52), "ba");
    }

    #[test]
    fn error_in_pass_run_recorded_as_verdict_error() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_n, _b| Err("boom".to_string())),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let any_err: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(&n.verdict, Verdict::Error { message } if message == "boom"));
        assert!(any_err);
    }

    fn stub_verdict(pass_id: &'static str, confidence: f32) -> DetectVerdict {
        DetectVerdict::new(
            pass_id,
            "tag",
            super::super::FAMILY_OBFUSCATOR_WRAPPER,
            confidence,
            10,
            vec![],
            String::new(),
        )
    }

    #[test]
    fn pass_node_base_carries_identity_and_defaults_output_absent() {
        let pick: DetectorPick = DetectorPick {
            pass: &PASS_A,
            verdict: stub_verdict("stub.a", 0.9),
        };
        let node: Node = pass_node_base(
            7,
            3,
            2,
            "branch-q".to_string(),
            [9u8; 32],
            128,
            "tag".to_string(),
            pick,
        );
        assert_eq!(node.id, 7);
        assert_eq!(node.parent_id, Some(3));
        assert_eq!(node.depth, 2);
        assert_eq!(node.branch_id, "branch-q");
        assert_eq!(node.pass_id.as_deref(), Some("stub.a"));
        assert_eq!(node.format_tag_in.as_deref(), Some("tag"));
        assert_eq!(node.input_blake3, [9u8; 32]);
        assert_eq!(node.input_size, 128);
        assert!(node.output_kind.is_none());
        assert!(node.output_blake3.is_none());
        assert!(node.output_size.is_none());
        assert!(node.output_bytes.is_none());
        assert!(node.duration.is_none());
        assert_eq!(node.picks.len(), 1);
        assert!(node.artifacts.is_empty());
        assert!(node.metadata.is_empty());
        assert!(matches!(node.verdict, Verdict::Ok));
    }

    fn self_reemit_via_mixed_fanout() -> RunnerFn {
        Box::new(|_n: u32, bytes: &[u8]| {
            Ok(PassRunOutcome {
                output_bytes: Vec::new(),
                kind: OutputKind::Mixed {
                    children: vec![ChildHandle {
                        artifact_index: 0,
                        relative_path: "self-echo.bin".to_string(),
                        hint: None,
                    }],
                },
                duration: Duration::from_millis(1),
                metadata: BTreeMap::new(),
                children: vec![bytes.to_vec()],
            })
        })
    }

    #[test]
    fn global_memo_halts_a_self_reemission_that_a_new_sibling_branch_lineage_would_not_catch() {
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: self_reemit_via_mixed_fanout(),
        };
        let d: ChainDriver<'_, CountingRunner> =
            ChainDriver::new(&r, &runner, ChainConfig::default());
        let spec: ChainSpec = ChainSpec::Auto { cap: 32 };
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);

        assert_eq!(
            runner.calls.load(AtomicOrdering::SeqCst),
            1,
            "OutputKind::Mixed never records into WorkItem.history (only OutputKind::Bytes does), \
             so the fresh sibling branch spawned for the echoed child carries a history set that \
             does not contain the repeat; only the global visited set can stop the pass from being \
             invoked a second time on the identical bytes"
        );
        let cycle_node: &Node = plan
            .nodes
            .iter()
            .find(|n: &&Node| matches!(n.verdict, Verdict::Cycle))
            .expect("the globally-repeated input must be recorded as a Cycle terminal");
        assert_eq!(
            cycle_node.depth, 2,
            "the duplicate must be caught on its first reappearance, not after grinding through the depth cap"
        );
        assert_ne!(
            cycle_node.branch_id, "a",
            "the catch must happen in the new sibling branch the mixed fan-out created, proving the \
             hit is not an artifact of the parent's own per-lineage history"
        );
        assert!(
            !plan
                .nodes
                .iter()
                .any(|n: &Node| matches!(n.verdict, Verdict::CapReached)),
            "without the global memo this would spawn a fresh branch every hop until the depth cap \
             fired instead; the run must halt via Cycle, not by exhausting the cap"
        );
    }

    #[test]
    fn fanout_expansion_is_bounded_by_cumulative_output_budget() {
        const CHILD_SIZE: usize = 4 * 1024 * 1024;
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|_n: u32, _b: &[u8]| {
                Ok(PassRunOutcome {
                    output_bytes: Vec::new(),
                    kind: OutputKind::Mixed {
                        children: vec![
                            ChildHandle {
                                artifact_index: 0,
                                relative_path: "a.bin".to_string(),
                                hint: None,
                            },
                            ChildHandle {
                                artifact_index: 1,
                                relative_path: "b.bin".to_string(),
                                hint: None,
                            },
                            ChildHandle {
                                artifact_index: 2,
                                relative_path: "c.bin".to_string(),
                                hint: None,
                            },
                        ],
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: vec![
                        vec![0xABu8; CHILD_SIZE],
                        vec![0xABu8; CHILD_SIZE],
                        vec![0xABu8; CHILD_SIZE],
                    ],
                })
            }),
        };
        let cfg: ChainConfig = ChainConfig {
            max_cumulative_output_bytes: 16 * 1024 * 1024,
            ..ChainConfig::default()
        };
        let d: ChainDriver<'_, CountingRunner> = ChainDriver::new(&r, &runner, cfg);
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let started: Instant = Instant::now();
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "decompression-bomb-style fan-out must terminate quickly under the output budget, took {elapsed:?}"
        );
        let calls: u32 = runner.calls.load(AtomicOrdering::SeqCst);
        assert_eq!(
            calls, 2,
            "the output budget must stop the traversal after the second pass run (3x4MiB then 3x4MiB again crosses the 16MiB budget), got {calls} calls"
        );
        let any_cap: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::CapReached));
        assert!(
            any_cap,
            "expected the cumulative output budget to terminal-layer unprocessed fan-out work as CapReached"
        );
    }

    #[test]
    fn non_identical_self_re_detecting_chain_bounded_by_output_budget_not_depth_cap() {
        const GROWTH_BYTES: usize = 2 * 1024 * 1024;
        let r: PassRegistry = registry_with_a();
        let runner: CountingRunner = CountingRunner {
            calls: AtomicU32::new(0),
            produce: Box::new(|n: u32, _b: &[u8]| {
                let mut v: Vec<u8> = format!("gen-{n}-").into_bytes();
                v.resize(GROWTH_BYTES, 0xCDu8);
                Ok(PassRunOutcome {
                    output_bytes: v,
                    kind: OutputKind::Bytes {
                        format_tag: "x",
                        family: super::super::FAMILY_OBFUSCATOR_WRAPPER,
                    },
                    duration: Duration::from_millis(1),
                    metadata: BTreeMap::new(),
                    children: Vec::new(),
                })
            }),
        };
        let cfg: ChainConfig = ChainConfig {
            max_cumulative_output_bytes: 10 * 1024 * 1024,
            ..ChainConfig::default()
        };
        let d: ChainDriver<'_, CountingRunner> = ChainDriver::new(&r, &runner, cfg);
        let spec: ChainSpec = ChainSpec::Auto {
            cap: super::super::spec::MAX_CAP,
        };
        let started: Instant = Instant::now();
        let plan: ChainPlan = d.run(b"seed".to_vec(), &spec, None);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "an ever-distinct re-emitting lineage must still terminate quickly, took {elapsed:?}"
        );
        let any_cycle: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::Cycle));
        assert!(
            !any_cycle,
            "each generation's output differs by its prefix, so the exact-byte-hash Cycle check must never fire here"
        );
        let any_cap: bool = plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::CapReached));
        assert!(
            any_cap,
            "expected the cumulative output budget to terminal-layer the runaway lineage as CapReached"
        );
        let calls: u32 = runner.calls.load(AtomicOrdering::SeqCst);
        assert_eq!(
            calls,
            6,
            "the 10MiB output budget must halt this lineage at generation 6 (6x2MiB), well before the depth cap of {}",
            super::super::spec::MAX_CAP
        );
    }
}
