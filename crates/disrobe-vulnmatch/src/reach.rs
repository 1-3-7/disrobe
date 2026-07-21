use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::adapters::{CallGraphView, DirectCall, FunctionId};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathWitness {
    pub functions: Vec<FunctionId>,
    pub distance: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "witness")]
pub enum ReachabilityState {
    Reachable(PathWitness),
    Unreachable,
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
            .cloned()
            .unwrap_or(ReachabilityState::Unknown)
    }
}

#[derive(Debug, Default)]
pub struct ReachabilityEngine;

impl ReachabilityEngine {
    pub fn analyze<C: CallGraphView>(call_graph: &C, budget: &mut Budget) -> ReachabilityResult {
        let all_functions: BTreeSet<FunctionId> = call_graph.functions().into_iter().collect();
        let selected_functions: BTreeSet<FunctionId> = Self::select_prefix(&all_functions, budget);
        let mut complete: bool = selected_functions.len() == all_functions.len();
        let mut adjacency: BTreeMap<FunctionId, BTreeSet<FunctionId>> = selected_functions
            .iter()
            .cloned()
            .map(|function: FunctionId| (function, BTreeSet::new()))
            .collect();
        let mut calls: Vec<DirectCall> = call_graph.direct_calls();
        calls.sort();
        for call in calls {
            if !budget.consume_step() {
                complete = false;
                break;
            }
            let Some(callee) = call.callee_function else {
                continue;
            };
            if selected_functions.contains(&call.caller) && selected_functions.contains(&callee) {
                if let Some(neighbors) = adjacency.get_mut(&call.caller) {
                    neighbors.insert(callee);
                } else {
                    complete = false;
                }
            } else if selected_functions.contains(&call.caller) {
                complete = false;
            }
        }
        let entries: BTreeSet<FunctionId> = call_graph.entry_points().into_iter().collect();
        let selected_entries: BTreeSet<FunctionId> = entries
            .iter()
            .filter(|entry: &&FunctionId| selected_functions.contains(*entry))
            .cloned()
            .collect();
        if selected_entries.len() != entries.len() {
            complete = false;
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
        let component_paths: BfsResult = breadth_first(
            &condensation.adjacency,
            &component_entries,
            budget.max_depth(),
            budget,
        );
        let function_paths: BfsResult =
            breadth_first(&adjacency, &selected_entries, budget.max_depth(), budget);
        complete = complete && component_paths.complete && function_paths.complete;
        let reachable_components: BTreeSet<FunctionId> =
            component_paths.nodes.keys().cloned().collect();
        let mut states: BTreeMap<FunctionId, ReachabilityState> = BTreeMap::new();
        for function in all_functions {
            let state: ReachabilityState = if !selected_functions.contains(&function) {
                ReachabilityState::Unknown
            } else if let Some(witness) = reconstruct_witness(&function, &function_paths.nodes) {
                ReachabilityState::Reachable(witness)
            } else if !complete {
                ReachabilityState::Unknown
            } else if condensation
                .component_of
                .get(&function)
                .is_some_and(|component: &FunctionId| !reachable_components.contains(component))
            {
                ReachabilityState::Unreachable
            } else {
                ReachabilityState::Unknown
            };
            states.insert(function, state);
        }
        ReachabilityResult { states, complete }
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
struct BfsNode {
    predecessor: Option<FunctionId>,
    depth: usize,
}

#[derive(Debug)]
struct BfsResult {
    nodes: BTreeMap<FunctionId, BfsNode>,
    complete: bool,
}

fn breadth_first(
    adjacency: &BTreeMap<FunctionId, BTreeSet<FunctionId>>,
    roots: &BTreeSet<FunctionId>,
    max_depth: usize,
    budget: &mut Budget,
) -> BfsResult {
    let mut nodes: BTreeMap<FunctionId, BfsNode> = BTreeMap::new();
    let mut queue: VecDeque<FunctionId> = VecDeque::new();
    for root in roots {
        nodes.insert(
            root.clone(),
            BfsNode {
                predecessor: None,
                depth: 0,
            },
        );
        queue.push_back(root.clone());
    }
    while let Some(node) = queue.pop_front() {
        let Some(current) = nodes.get(&node) else {
            return BfsResult {
                nodes,
                complete: false,
            };
        };
        let depth: usize = current.depth;
        let Some(neighbors) = adjacency.get(&node) else {
            return BfsResult {
                nodes,
                complete: false,
            };
        };
        if depth >= max_depth {
            if !neighbors.is_empty() {
                budget.mark_depth_limit_reached();
                return BfsResult {
                    nodes,
                    complete: false,
                };
            }
            continue;
        }
        for neighbor in neighbors {
            if !budget.consume_step() {
                return BfsResult {
                    nodes,
                    complete: false,
                };
            }
            if !nodes.contains_key(neighbor) {
                nodes.insert(
                    neighbor.clone(),
                    BfsNode {
                        predecessor: Some(node.clone()),
                        depth: depth.saturating_add(1),
                    },
                );
                queue.push_back(neighbor.clone());
            }
        }
    }
    BfsResult {
        nodes,
        complete: true,
    }
}

fn reconstruct_witness(
    destination: &FunctionId,
    nodes: &BTreeMap<FunctionId, BfsNode>,
) -> Option<PathWitness> {
    let destination_node: &BfsNode = nodes.get(destination)?;
    let mut reverse_path: Vec<FunctionId> = Vec::new();
    let mut cursor: FunctionId = destination.clone();
    loop {
        reverse_path.push(cursor.clone());
        let node: &BfsNode = nodes.get(&cursor)?;
        let Some(predecessor) = &node.predecessor else {
            break;
        };
        cursor = predecessor.clone();
    }
    reverse_path.reverse();
    Some(PathWitness {
        functions: reverse_path,
        distance: destination_node.depth,
    })
}
