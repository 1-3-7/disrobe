use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::adapters::{
    CallGraphEdge, CallGraphView, CallSiteId, EdgeKind, FunctionId,
    MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    max_nodes: usize,
    max_depth: usize,
    max_steps: usize,
    nodes_used: usize,
    steps_used: usize,
    node_limit_reached: bool,
    step_limit_reached: bool,
    depth_limit_reached: bool,
}

impl Budget {
    pub const fn new(max_nodes: usize, max_depth: usize) -> Self {
        let computed_steps: usize = max_nodes.saturating_mul(max_nodes).saturating_mul(16);
        let derived_steps: usize = if computed_steps == 0 {
            1
        } else {
            computed_steps
        };
        Self::with_step_limit(max_nodes, max_depth, derived_steps)
    }

    pub const fn with_step_limit(max_nodes: usize, max_depth: usize, max_steps: usize) -> Self {
        Self {
            max_nodes,
            max_depth,
            max_steps,
            nodes_used: 0,
            steps_used: 0,
            node_limit_reached: false,
            step_limit_reached: false,
            depth_limit_reached: false,
        }
    }

    pub const fn nodes_used(&self) -> usize {
        self.nodes_used
    }

    pub const fn node_limit_reached(&self) -> bool {
        self.node_limit_reached
    }

    pub const fn step_limit_reached(&self) -> bool {
        self.step_limit_reached
    }

    pub const fn depth_limit_reached(&self) -> bool {
        self.depth_limit_reached
    }

    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    pub(crate) const fn consume_node(&mut self) -> bool {
        if self.nodes_used >= self.max_nodes {
            self.node_limit_reached = true;
            return false;
        }
        self.nodes_used += 1;
        true
    }

    pub(crate) const fn consume_step(&mut self) -> bool {
        if self.steps_used >= self.max_steps {
            self.step_limit_reached = true;
            return false;
        }
        self.steps_used += 1;
        true
    }

    const fn mark_depth_limit_reached(&mut self) {
        self.depth_limit_reached = true;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeSoundness {
    Unknown,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathWitness {
    pub functions: Vec<FunctionId>,
    pub distance: usize,
    pub weakest_edge_soundness: EdgeSoundness,
    pub terminal_unresolved_call: Option<CallSiteId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "witness")]
pub enum ReachabilityState {
    Reachable(PathWitness),
    Unreachable,
    ReachabilityUnknown(PathWitness),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityResult {
    states: BTreeMap<FunctionId, ReachabilityState>,
    pub complete: bool,
}

impl ReachabilityResult {
    pub fn state(&self, function: &FunctionId) -> ReachabilityState {
        self.states
            .get(function)
            .map_or(ReachabilityState::Unknown, |state: &ReachabilityState| {
                state.clone()
            })
    }
}

#[derive(Debug, Default)]
pub struct ReachabilityEngine;

impl ReachabilityEngine {
    pub fn analyze<C: CallGraphView>(call_graph: &C, budget: &mut Budget) -> ReachabilityResult {
        let all_functions: BTreeSet<FunctionId> = call_graph.functions().into_iter().collect();
        let selected_functions: BTreeSet<FunctionId> = Self::select_prefix(&all_functions, budget);
        let mut traversal_complete: bool = selected_functions.len() == all_functions.len();
        let mut adjacency: BTreeMap<FunctionId, BTreeSet<FunctionId>> = selected_functions
            .iter()
            .cloned()
            .map(|function: FunctionId| (function, BTreeSet::new()))
            .collect();
        let mut witness_adjacency: BTreeMap<FunctionId, BTreeMap<FunctionId, EdgeSoundness>> =
            selected_functions
                .iter()
                .cloned()
                .map(|function: FunctionId| (function, BTreeMap::new()))
                .collect();
        let mut unresolved_by_caller: BTreeMap<FunctionId, BTreeSet<CallSiteId>> = BTreeMap::new();
        let mut edges: Vec<CallGraphEdge> = call_graph.call_edges();
        edges.sort();
        edges.dedup();
        for edge in edges {
            if !budget.consume_step() {
                traversal_complete = false;
                break;
            }
            if !all_functions.contains(&edge.caller) {
                traversal_complete = false;
                continue;
            }
            if !selected_functions.contains(&edge.caller) {
                continue;
            }
            match normalize_edge_kind(&edge.kind) {
                NormalizedEdgeKind::Known { callees, soundness } => {
                    for callee in callees {
                        if !selected_functions.contains(&callee) {
                            traversal_complete = false;
                            continue;
                        }
                        if !insert_known_edge(
                            &mut adjacency,
                            &mut witness_adjacency,
                            &edge.caller,
                            callee,
                            soundness,
                        ) {
                            traversal_complete = false;
                        }
                    }
                }
                NormalizedEdgeKind::UnresolvedIndirect => {
                    unresolved_by_caller
                        .entry(edge.caller)
                        .or_default()
                        .insert(edge.id);
                }
                NormalizedEdgeKind::Ignored => {}
            }
        }
        let entries: BTreeSet<FunctionId> = call_graph.entry_points().into_iter().collect();
        let selected_entries: BTreeSet<FunctionId> = entries
            .iter()
            .filter(|entry: &&FunctionId| selected_functions.contains(*entry))
            .cloned()
            .collect();
        if selected_entries.len() != entries.len() {
            traversal_complete = false;
        }
        let Some(components) = tarjan_components(&adjacency, &selected_functions, budget) else {
            return Self::incomplete_result(&all_functions, &selected_entries);
        };
        let Some(condensation) = build_condensation(&adjacency, &components, budget) else {
            return Self::incomplete_result(&all_functions, &selected_entries);
        };
        let component_entries: BTreeSet<FunctionId> = selected_entries
            .iter()
            .filter_map(|entry: &FunctionId| condensation.component_of.get(entry).cloned())
            .collect();
        let component_paths: NodeBfsResult = breadth_first_nodes(
            &condensation.adjacency,
            &component_entries,
            budget.max_depth(),
            budget,
        );
        let function_paths: WitnessBfsResult = breadth_first_witnesses(
            &witness_adjacency,
            &selected_entries,
            budget.max_depth(),
            budget,
        );
        traversal_complete =
            traversal_complete && component_paths.complete && function_paths.complete;
        let unresolved_paths: UnresolvedWitnessResult = unresolved_witness(
            &unresolved_by_caller,
            &function_paths.nodes,
            budget.max_depth(),
        );
        if !unresolved_paths.complete {
            budget.mark_depth_limit_reached();
            traversal_complete = false;
        }
        let unresolved_witness: Option<PathWitness> = unresolved_paths.witness;
        let mut states: BTreeMap<FunctionId, ReachabilityState> = BTreeMap::new();
        for function in all_functions {
            let state: ReachabilityState = if !selected_functions.contains(&function) {
                ReachabilityState::Unknown
            } else if let Some(witness) = reconstruct_witness(&function, &function_paths.nodes) {
                ReachabilityState::Reachable(witness)
            } else if !traversal_complete {
                ReachabilityState::Unknown
            } else if let Some(witness) = &unresolved_witness {
                ReachabilityState::ReachabilityUnknown(witness.clone())
            } else if condensation
                .component_of
                .get(&function)
                .is_some_and(|component: &FunctionId| !component_paths.nodes.contains(component))
            {
                ReachabilityState::Unreachable
            } else {
                ReachabilityState::Unknown
            };
            states.insert(function, state);
        }
        ReachabilityResult {
            states,
            complete: traversal_complete && unresolved_witness.is_none(),
        }
    }

    fn select_prefix(
        functions: &BTreeSet<FunctionId>,
        budget: &mut Budget,
    ) -> BTreeSet<FunctionId> {
        let mut selected: BTreeSet<FunctionId> = BTreeSet::new();
        for function in functions {
            if !budget.consume_node() {
                break;
            }
            selected.insert(function.clone());
        }
        selected
    }

    fn incomplete_result(
        all_functions: &BTreeSet<FunctionId>,
        selected_entries: &BTreeSet<FunctionId>,
    ) -> ReachabilityResult {
        let mut states: BTreeMap<FunctionId, ReachabilityState> = BTreeMap::new();
        for function in all_functions {
            let state: ReachabilityState = if selected_entries.contains(function) {
                ReachabilityState::Reachable(PathWitness {
                    functions: vec![function.clone()],
                    distance: 0,
                    weakest_edge_soundness: EdgeSoundness::High,
                    terminal_unresolved_call: None,
                })
            } else {
                ReachabilityState::Unknown
            };
            states.insert(function.clone(), state);
        }
        ReachabilityResult {
            states,
            complete: false,
        }
    }
}

#[derive(Debug)]
enum NormalizedEdgeKind {
    Known {
        callees: BTreeSet<FunctionId>,
        soundness: EdgeSoundness,
    },
    UnresolvedIndirect,
    Ignored,
}

fn normalize_edge_kind(kind: &EdgeKind) -> NormalizedEdgeKind {
    match kind {
        EdgeKind::Direct {
            callee: Some(callee),
        } => NormalizedEdgeKind::Known {
            callees: BTreeSet::from([callee.clone()]),
            soundness: EdgeSoundness::High,
        },
        EdgeKind::Direct { callee: None } => NormalizedEdgeKind::Ignored,
        EdgeKind::ResolvedIndirect { candidates }
            if candidates.is_empty()
                || candidates.len() > MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE =>
        {
            NormalizedEdgeKind::UnresolvedIndirect
        }
        EdgeKind::ResolvedIndirect { candidates } => NormalizedEdgeKind::Known {
            callees: candidates.clone(),
            soundness: EdgeSoundness::Medium,
        },
        EdgeKind::UnresolvedIndirect => NormalizedEdgeKind::UnresolvedIndirect,
    }
}

fn insert_known_edge(
    adjacency: &mut BTreeMap<FunctionId, BTreeSet<FunctionId>>,
    witness_adjacency: &mut BTreeMap<FunctionId, BTreeMap<FunctionId, EdgeSoundness>>,
    caller: &FunctionId,
    callee: FunctionId,
    soundness: EdgeSoundness,
) -> bool {
    let Some(neighbors) = adjacency.get_mut(caller) else {
        return false;
    };
    neighbors.insert(callee.clone());
    let Some(witness_neighbors) = witness_adjacency.get_mut(caller) else {
        return false;
    };
    match witness_neighbors.get(&callee) {
        Some(existing) if *existing >= soundness => true,
        _ => {
            witness_neighbors.insert(callee, soundness);
            true
        }
    }
}

#[derive(Debug)]
struct Condensation {
    component_of: BTreeMap<FunctionId, FunctionId>,
    adjacency: BTreeMap<FunctionId, BTreeSet<FunctionId>>,
}

fn build_condensation(
    adjacency: &BTreeMap<FunctionId, BTreeSet<FunctionId>>,
    components: &BTreeMap<FunctionId, BTreeSet<FunctionId>>,
    budget: &mut Budget,
) -> Option<Condensation> {
    let mut component_of: BTreeMap<FunctionId, FunctionId> = BTreeMap::new();
    for (component, members) in components {
        for member in members {
            component_of.insert(member.clone(), component.clone());
        }
    }
    let mut condensed: BTreeMap<FunctionId, BTreeSet<FunctionId>> = components
        .keys()
        .cloned()
        .map(|component: FunctionId| (component, BTreeSet::new()))
        .collect();
    for (caller, callees) in adjacency {
        let caller_component: FunctionId = component_of.get(caller)?.clone();
        for callee in callees {
            if !budget.consume_step() {
                return None;
            }
            let callee_component: FunctionId = component_of.get(callee)?.clone();
            if caller_component != callee_component {
                let targets: &mut BTreeSet<FunctionId> = condensed.get_mut(&caller_component)?;
                targets.insert(callee_component);
            }
        }
    }
    Some(Condensation {
        component_of,
        adjacency: condensed,
    })
}

#[derive(Debug)]
struct TarjanFrame {
    node: FunctionId,
    neighbors: Vec<FunctionId>,
    next_neighbor: usize,
}

fn tarjan_components(
    adjacency: &BTreeMap<FunctionId, BTreeSet<FunctionId>>,
    nodes: &BTreeSet<FunctionId>,
    budget: &mut Budget,
) -> Option<BTreeMap<FunctionId, BTreeSet<FunctionId>>> {
    let mut indices: BTreeMap<FunctionId, usize> = BTreeMap::new();
    let mut lowlinks: BTreeMap<FunctionId, usize> = BTreeMap::new();
    let mut stack: Vec<FunctionId> = Vec::new();
    let mut on_stack: BTreeSet<FunctionId> = BTreeSet::new();
    let mut next_index: usize = 0;
    let mut components: BTreeMap<FunctionId, BTreeSet<FunctionId>> = BTreeMap::new();
    for root in nodes {
        if indices.contains_key(root) {
            continue;
        }
        if !budget.consume_step() {
            return None;
        }
        visit_tarjan_node(
            root.clone(),
            &mut indices,
            &mut lowlinks,
            &mut stack,
            &mut on_stack,
            &mut next_index,
        );
        let root_neighbors: Vec<FunctionId> = adjacency.get(root)?.iter().cloned().collect();
        let mut frames: Vec<TarjanFrame> = vec![TarjanFrame {
            node: root.clone(),
            neighbors: root_neighbors,
            next_neighbor: 0,
        }];
        while !frames.is_empty() {
            let frame_index: usize = frames.len().saturating_sub(1);
            let next_neighbor: Option<FunctionId> = {
                let frame: &mut TarjanFrame = frames.get_mut(frame_index)?;
                if frame.next_neighbor < frame.neighbors.len() {
                    let neighbor: FunctionId = frame.neighbors.get(frame.next_neighbor)?.clone();
                    frame.next_neighbor += 1;
                    Some(neighbor)
                } else {
                    None
                }
            };
            if let Some(neighbor) = next_neighbor {
                if !budget.consume_step() {
                    return None;
                }
                if !indices.contains_key(&neighbor) {
                    visit_tarjan_node(
                        neighbor.clone(),
                        &mut indices,
                        &mut lowlinks,
                        &mut stack,
                        &mut on_stack,
                        &mut next_index,
                    );
                    let neighbors: Vec<FunctionId> =
                        adjacency.get(&neighbor)?.iter().cloned().collect();
                    frames.push(TarjanFrame {
                        node: neighbor,
                        neighbors,
                        next_neighbor: 0,
                    });
                } else if on_stack.contains(&neighbor) {
                    let node: FunctionId = frames.get(frame_index)?.node.clone();
                    let neighbor_index: usize = *indices.get(&neighbor)?;
                    let node_lowlink: usize = *lowlinks.get(&node)?;
                    if neighbor_index < node_lowlink {
                        lowlinks.insert(node, neighbor_index);
                    }
                }
                continue;
            }
            let completed: TarjanFrame = frames.pop()?;
            let node_index: usize = *indices.get(&completed.node)?;
            let node_lowlink: usize = *lowlinks.get(&completed.node)?;
            if node_lowlink == node_index {
                let mut members: BTreeSet<FunctionId> = BTreeSet::new();
                loop {
                    let member: FunctionId = stack.pop()?;
                    on_stack.remove(&member);
                    let is_root: bool = member == completed.node;
                    members.insert(member);
                    if is_root {
                        break;
                    }
                }
                let component: FunctionId = members.first()?.clone();
                components.insert(component, members);
            }
            if let Some(parent) = frames.last() {
                let parent_lowlink: usize = *lowlinks.get(&parent.node)?;
                if node_lowlink < parent_lowlink {
                    lowlinks.insert(parent.node.clone(), node_lowlink);
                }
            }
        }
    }
    Some(components)
}

fn visit_tarjan_node(
    node: FunctionId,
    indices: &mut BTreeMap<FunctionId, usize>,
    lowlinks: &mut BTreeMap<FunctionId, usize>,
    stack: &mut Vec<FunctionId>,
    on_stack: &mut BTreeSet<FunctionId>,
    next_index: &mut usize,
) {
    let index: usize = *next_index;
    *next_index = next_index.saturating_add(1);
    indices.insert(node.clone(), index);
    lowlinks.insert(node.clone(), index);
    stack.push(node.clone());
    on_stack.insert(node);
}

#[derive(Debug)]
struct NodeBfsResult {
    nodes: BTreeSet<FunctionId>,
    complete: bool,
}

fn breadth_first_nodes(
    adjacency: &BTreeMap<FunctionId, BTreeSet<FunctionId>>,
    roots: &BTreeSet<FunctionId>,
    max_depth: usize,
    budget: &mut Budget,
) -> NodeBfsResult {
    let mut nodes: BTreeMap<FunctionId, usize> = BTreeMap::new();
    let mut queue: VecDeque<FunctionId> = VecDeque::new();
    for root in roots {
        nodes.insert(root.clone(), 0);
        queue.push_back(root.clone());
    }
    while let Some(node) = queue.pop_front() {
        let Some(depth) = nodes.get(&node).copied() else {
            return NodeBfsResult {
                nodes: nodes.keys().cloned().collect(),
                complete: false,
            };
        };
        let Some(neighbors) = adjacency.get(&node) else {
            return NodeBfsResult {
                nodes: nodes.keys().cloned().collect(),
                complete: false,
            };
        };
        if depth >= max_depth {
            if !neighbors.is_empty() {
                budget.mark_depth_limit_reached();
                return NodeBfsResult {
                    nodes: nodes.keys().cloned().collect(),
                    complete: false,
                };
            }
            continue;
        }
        for neighbor in neighbors {
            if !budget.consume_step() {
                return NodeBfsResult {
                    nodes: nodes.keys().cloned().collect(),
                    complete: false,
                };
            }
            if !nodes.contains_key(neighbor) {
                nodes.insert(neighbor.clone(), depth.saturating_add(1));
                queue.push_back(neighbor.clone());
            }
        }
    }
    NodeBfsResult {
        nodes: nodes.keys().cloned().collect(),
        complete: true,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BfsKey {
    function: FunctionId,
    soundness: EdgeSoundness,
}

#[derive(Debug)]
struct WitnessBfsNode {
    predecessor: Option<BfsKey>,
    depth: usize,
}

#[derive(Debug)]
struct WitnessBfsResult {
    nodes: BTreeMap<BfsKey, WitnessBfsNode>,
    complete: bool,
}

fn breadth_first_witnesses(
    adjacency: &BTreeMap<FunctionId, BTreeMap<FunctionId, EdgeSoundness>>,
    roots: &BTreeSet<FunctionId>,
    max_depth: usize,
    budget: &mut Budget,
) -> WitnessBfsResult {
    let mut nodes: BTreeMap<BfsKey, WitnessBfsNode> = BTreeMap::new();
    let mut queue: VecDeque<BfsKey> = VecDeque::new();
    for root in roots {
        let key: BfsKey = BfsKey {
            function: root.clone(),
            soundness: EdgeSoundness::High,
        };
        nodes.insert(
            key.clone(),
            WitnessBfsNode {
                predecessor: None,
                depth: 0,
            },
        );
        queue.push_back(key);
    }
    while let Some(key) = queue.pop_front() {
        let Some(depth) = nodes.get(&key).map(|node: &WitnessBfsNode| node.depth) else {
            return WitnessBfsResult {
                nodes,
                complete: false,
            };
        };
        let Some(neighbors) = adjacency.get(&key.function) else {
            return WitnessBfsResult {
                nodes,
                complete: false,
            };
        };
        if depth >= max_depth {
            if !neighbors.is_empty() {
                budget.mark_depth_limit_reached();
                return WitnessBfsResult {
                    nodes,
                    complete: false,
                };
            }
            continue;
        }
        for (neighbor, edge_soundness) in neighbors {
            if !budget.consume_step() {
                return WitnessBfsResult {
                    nodes,
                    complete: false,
                };
            }
            let next: BfsKey = BfsKey {
                function: neighbor.clone(),
                soundness: key.soundness.min(*edge_soundness),
            };
            if !nodes.contains_key(&next) {
                nodes.insert(
                    next.clone(),
                    WitnessBfsNode {
                        predecessor: Some(key.clone()),
                        depth: depth.saturating_add(1),
                    },
                );
                queue.push_back(next);
            }
        }
    }
    WitnessBfsResult {
        nodes,
        complete: true,
    }
}

fn reconstruct_witness(
    destination: &FunctionId,
    nodes: &BTreeMap<BfsKey, WitnessBfsNode>,
) -> Option<PathWitness> {
    let destination_key: BfsKey = strongest_witness_key(destination, nodes)?;
    let destination_node: &WitnessBfsNode = nodes.get(&destination_key)?;
    let mut reverse_path: Vec<FunctionId> = Vec::new();
    let mut cursor: BfsKey = destination_key.clone();
    loop {
        reverse_path.push(cursor.function.clone());
        let node: &WitnessBfsNode = nodes.get(&cursor)?;
        let Some(predecessor) = &node.predecessor else {
            break;
        };
        cursor = predecessor.clone();
    }
    reverse_path.reverse();
    Some(PathWitness {
        functions: reverse_path,
        distance: destination_node.depth,
        weakest_edge_soundness: destination_key.soundness,
        terminal_unresolved_call: None,
    })
}

fn strongest_witness_key(
    destination: &FunctionId,
    nodes: &BTreeMap<BfsKey, WitnessBfsNode>,
) -> Option<BfsKey> {
    let high: BfsKey = BfsKey {
        function: destination.clone(),
        soundness: EdgeSoundness::High,
    };
    if nodes.contains_key(&high) {
        return Some(high);
    }
    let medium: BfsKey = BfsKey {
        function: destination.clone(),
        soundness: EdgeSoundness::Medium,
    };
    if nodes.contains_key(&medium) {
        return Some(medium);
    }
    None
}

#[derive(Debug)]
struct UnresolvedWitnessResult {
    witness: Option<PathWitness>,
    complete: bool,
}

fn unresolved_witness(
    unresolved_by_caller: &BTreeMap<FunctionId, BTreeSet<CallSiteId>>,
    nodes: &BTreeMap<BfsKey, WitnessBfsNode>,
    max_depth: usize,
) -> UnresolvedWitnessResult {
    let mut witness: Option<PathWitness> = None;
    let mut complete: bool = true;
    for (caller, call_sites) in unresolved_by_caller {
        let Some(source_witness) = reconstruct_witness(caller, nodes) else {
            continue;
        };
        if source_witness.distance >= max_depth {
            complete = false;
            continue;
        }
        let Some(call_site) = call_sites.first() else {
            continue;
        };
        if witness.is_none() {
            witness = Some(PathWitness {
                functions: source_witness.functions,
                distance: source_witness.distance.saturating_add(1),
                weakest_edge_soundness: EdgeSoundness::Unknown,
                terminal_unresolved_call: Some(call_site.clone()),
            });
        }
    }
    UnresolvedWitnessResult { witness, complete }
}
