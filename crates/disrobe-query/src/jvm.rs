use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;

pub const MAX_JVM_HIERARCHY_NODES: usize = 16_384;
pub const MAX_JVM_HIERARCHY_EDGES: usize = 65_536;
pub const MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES: usize = 1_048_576;
pub const MAX_JVM_IMPLEMENTOR_MATCHES: usize = 16_384;
pub const MAX_JVM_PROOF_DEPTH: usize = 256;
pub const MAX_JVM_PROOF_ELEMENTS: usize = 65_536;
pub const MAX_JVM_PROOF_BYTES: usize = 1_048_576;
const MAX_JVM_MISSING_DEFINITION_DIAGNOSTICS: usize = 16_384;
const MAX_JVM_MALFORMED_DESCRIPTOR_DIAGNOSTICS: usize = 16_384;
const MAX_JVM_MALFORMED_DESCRIPTOR_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JvmTypeKind {
    Interface,
    Abstract,
    Concrete,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct JvmHierarchyNode {
    pub descriptor: String,
    pub kind: JvmTypeKind,
    pub parents: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JvmHierarchyDiagnostic {
    InvalidTarget { descriptor: String },
    MissingTarget { descriptor: String },
    ConcreteTarget { descriptor: String },
    MalformedDescriptor { descriptor: String },
    MissingDefinition { child: String, parent: String },
    RejectedArtifact { artifact: String },
    DuplicateDefinition { descriptor: String },
    SelfEdge { descriptor: String },
    Cycle { descriptors: Vec<String> },
    NodeLimit { max: usize },
    EdgeLimit { max: usize },
    DescriptorBytesLimit { max: usize },
    TargetDescriptorBytesLimit { max: usize },
    MatchLimit { max: usize },
    ProofDepthLimit { max: usize },
    ProofElementsLimit { max: usize },
    ProofBytesLimit { max: usize },
    MissingDefinitionDiagnosticLimit { max: usize, max_bytes: usize },
    RejectedArtifactDiagnosticLimit { max: usize, max_bytes: usize },
    MalformedDescriptorDiagnosticLimit { max: usize, max_bytes: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JvmImplementorMatch {
    pub descriptor: String,
    pub proof_path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JvmImplementorResult {
    pub target: String,
    pub matches: Vec<JvmImplementorMatch>,
    pub diagnostics: Vec<JvmHierarchyDiagnostic>,
}

#[must_use]
pub fn resolve_jvm_implementors(target: &str, nodes: &[JvmHierarchyNode]) -> JvmImplementorResult {
    if target.len() > MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES {
        let mut end: usize = MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES;
        while !target.is_char_boundary(end) {
            end -= 1;
        }
        return JvmImplementorResult {
            target: target[..end].to_owned(),
            matches: Vec::new(),
            diagnostics: vec![JvmHierarchyDiagnostic::TargetDescriptorBytesLimit {
                max: MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES,
            }],
        };
    }
    let mut diagnostics: BTreeSet<JvmHierarchyDiagnostic> = BTreeSet::new();
    if !is_type_descriptor(target) {
        diagnostics.insert(JvmHierarchyDiagnostic::InvalidTarget {
            descriptor: target.to_owned(),
        });
    }
    let graph: BTreeMap<String, JvmHierarchyNode> =
        canonical_graph(nodes, target, &mut diagnostics);
    if graph
        .get(target)
        .is_some_and(|node: &JvmHierarchyNode| node.kind == JvmTypeKind::Concrete)
    {
        diagnostics.insert(JvmHierarchyDiagnostic::ConcreteTarget {
            descriptor: target.to_owned(),
        });
    }
    let mut graph = graph;
    enforce_edge_limit(&mut graph, &mut diagnostics);
    let mut missing_diagnostic_count: usize = 0;
    let mut missing_diagnostic_bytes: usize = 0;
    let mut missing_diagnostics_truncated: bool = false;
    for node in graph.values() {
        for parent in &node.parents {
            if parent == &node.descriptor {
                diagnostics.insert(JvmHierarchyDiagnostic::SelfEdge {
                    descriptor: node.descriptor.clone(),
                });
            } else if !graph.contains_key(parent)
                && missing_diagnostic_count < MAX_JVM_MISSING_DEFINITION_DIAGNOSTICS
                && missing_diagnostic_bytes
                    .saturating_add(node.descriptor.len())
                    .saturating_add(parent.len())
                    <= MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES
            {
                missing_diagnostic_count += 1;
                missing_diagnostic_bytes += node.descriptor.len() + parent.len();
                diagnostics.insert(JvmHierarchyDiagnostic::MissingDefinition {
                    child: node.descriptor.clone(),
                    parent: parent.clone(),
                });
            } else if !graph.contains_key(parent) {
                missing_diagnostics_truncated = true;
            }
        }
    }
    if missing_diagnostics_truncated {
        diagnostics.insert(JvmHierarchyDiagnostic::MissingDefinitionDiagnosticLimit {
            max: MAX_JVM_MISSING_DEFINITION_DIAGNOSTICS,
            max_bytes: MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES,
        });
    }
    for cycle in cycles(&graph) {
        diagnostics.insert(JvmHierarchyDiagnostic::Cycle { descriptors: cycle });
    }
    let mut matches: Vec<JvmImplementorMatch> = Vec::new();
    if is_type_descriptor(target) {
        if let Some(target_node) = graph.get(target) {
            if target_node.kind != JvmTypeKind::Concrete {
                let predecessors: BTreeMap<&str, &str> =
                    predecessors(&graph, target, &mut diagnostics);
                let mut proof_elements: usize = 0;
                let mut proof_bytes: usize = 0;
                for node in graph
                    .values()
                    .filter(|node: &&JvmHierarchyNode| node.kind == JvmTypeKind::Concrete)
                {
                    if predecessors.contains_key(node.descriptor.as_str()) {
                        let Some(proof_path) = reconstruct_path(
                            &predecessors,
                            &node.descriptor,
                            target,
                            &mut diagnostics,
                        ) else {
                            continue;
                        };
                        let path_bytes: usize = proof_path.iter().map(String::len).sum();
                        if matches.len() == MAX_JVM_IMPLEMENTOR_MATCHES {
                            diagnostics.insert(JvmHierarchyDiagnostic::MatchLimit {
                                max: MAX_JVM_IMPLEMENTOR_MATCHES,
                            });
                            break;
                        }
                        if proof_elements.saturating_add(proof_path.len()) > MAX_JVM_PROOF_ELEMENTS
                        {
                            diagnostics.insert(JvmHierarchyDiagnostic::ProofElementsLimit {
                                max: MAX_JVM_PROOF_ELEMENTS,
                            });
                            break;
                        }
                        if proof_bytes.saturating_add(path_bytes) > MAX_JVM_PROOF_BYTES {
                            diagnostics.insert(JvmHierarchyDiagnostic::ProofBytesLimit {
                                max: MAX_JVM_PROOF_BYTES,
                            });
                            break;
                        }
                        proof_elements += proof_path.len();
                        proof_bytes += path_bytes;
                        matches.push(JvmImplementorMatch {
                            descriptor: node.descriptor.clone(),
                            proof_path,
                        });
                    }
                }
            }
        } else {
            diagnostics.insert(JvmHierarchyDiagnostic::MissingTarget {
                descriptor: target.to_owned(),
            });
        }
    }
    matches.sort_by(|left: &JvmImplementorMatch, right: &JvmImplementorMatch| {
        left.descriptor
            .cmp(&right.descriptor)
            .then(left.proof_path.cmp(&right.proof_path))
    });
    JvmImplementorResult {
        target: target.to_owned(),
        matches,
        diagnostics: diagnostics.into_iter().collect(),
    }
}

fn canonical_graph(
    nodes: &[JvmHierarchyNode],
    target: &str,
    diagnostics: &mut BTreeSet<JvmHierarchyDiagnostic>,
) -> BTreeMap<String, JvmHierarchyNode> {
    let mut canonical_nodes: BTreeSet<JvmHierarchyNode> = BTreeSet::new();
    let mut malformed: MalformedDescriptorSelection<'_> = MalformedDescriptorSelection::default();
    for node in nodes {
        let Some(canonical) = canonical_node(node, diagnostics, &mut malformed) else {
            continue;
        };
        if canonical_nodes.contains(&canonical) {
            continue;
        }
        if canonical_nodes.len() == MAX_JVM_HIERARCHY_NODES {
            let eviction: Option<JvmHierarchyNode> = if canonical.descriptor == target {
                canonical_nodes
                    .iter()
                    .rev()
                    .find(|candidate: &&JvmHierarchyNode| candidate.descriptor != target)
                    .or_else(|| canonical_nodes.last())
                    .cloned()
            } else {
                canonical_nodes
                    .iter()
                    .rev()
                    .find(|candidate: &&JvmHierarchyNode| candidate.descriptor != target)
                    .filter(|candidate: &&JvmHierarchyNode| canonical < **candidate)
                    .cloned()
            };
            let Some(eviction) = eviction else {
                diagnostics.insert(JvmHierarchyDiagnostic::NodeLimit {
                    max: MAX_JVM_HIERARCHY_NODES,
                });
                continue;
            };
            canonical_nodes.remove(&eviction);
            diagnostics.insert(JvmHierarchyDiagnostic::NodeLimit {
                max: MAX_JVM_HIERARCHY_NODES,
            });
        }
        canonical_nodes.insert(canonical);
    }
    malformed.emit(diagnostics);
    let selected: BTreeSet<JvmHierarchyNode> = canonical_nodes;
    let mut admitted: Vec<JvmHierarchyNode> = Vec::new();
    let mut descriptor_bytes: usize = 0;
    for node in selected {
        if admitted.len() == MAX_JVM_HIERARCHY_NODES {
            break;
        }
        let node_bytes: usize = node
            .descriptor
            .len()
            .saturating_add(node.parents.iter().map(String::len).sum::<usize>());
        if descriptor_bytes.saturating_add(node_bytes) > MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES {
            diagnostics.insert(JvmHierarchyDiagnostic::DescriptorBytesLimit {
                max: MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES,
            });
            continue;
        }
        descriptor_bytes += node_bytes;
        admitted.push(node);
    }
    let mut graph: BTreeMap<String, JvmHierarchyNode> = BTreeMap::new();
    let mut grouped: BTreeMap<String, Vec<JvmHierarchyNode>> = BTreeMap::new();
    for node in admitted {
        grouped
            .entry(node.descriptor.clone())
            .or_default()
            .push(node);
    }
    for (descriptor, definitions) in grouped {
        if definitions.len() != 1 {
            diagnostics.insert(JvmHierarchyDiagnostic::DuplicateDefinition { descriptor });
            continue;
        }
        if let Some(node) = definitions.into_iter().next() {
            graph.insert(node.descriptor.clone(), node);
        }
    }
    graph
}

fn canonical_node<'a>(
    node: &'a JvmHierarchyNode,
    diagnostics: &mut BTreeSet<JvmHierarchyDiagnostic>,
    malformed: &mut MalformedDescriptorSelection<'a>,
) -> Option<JvmHierarchyNode> {
    if !is_type_descriptor(&node.descriptor) {
        malformed.observe(&node.descriptor);
        return None;
    }
    if node.descriptor.len() > MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES {
        diagnostics.insert(JvmHierarchyDiagnostic::DescriptorBytesLimit {
            max: MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES,
        });
        return None;
    }
    let mut selected: BTreeSet<&str> = BTreeSet::new();
    for parent in &node.parents {
        if !is_type_descriptor(parent) {
            malformed.observe(parent);
            continue;
        }
        if selected.contains(parent.as_str()) {
            continue;
        }
        selected.insert(parent);
        if selected.len() > MAX_JVM_HIERARCHY_EDGES {
            selected.pop_last();
            diagnostics.insert(JvmHierarchyDiagnostic::EdgeLimit {
                max: MAX_JVM_HIERARCHY_EDGES,
            });
        }
    }
    let mut parent_bytes: usize = node.descriptor.len();
    let mut parents: Vec<String> = Vec::new();
    for parent in selected {
        if parent_bytes.saturating_add(parent.len()) > MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES {
            diagnostics.insert(JvmHierarchyDiagnostic::DescriptorBytesLimit {
                max: MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES,
            });
            break;
        }
        parent_bytes += parent.len();
        parents.push(parent.to_owned());
    }
    Some(JvmHierarchyNode {
        descriptor: node.descriptor.clone(),
        kind: node.kind,
        parents,
    })
}

#[derive(Default)]
struct MalformedDescriptorSelection<'a> {
    values: BTreeSet<&'a str>,
    truncated: bool,
}

impl<'a> MalformedDescriptorSelection<'a> {
    fn observe(&mut self, descriptor: &'a str) {
        if self.values.contains(descriptor) {
            return;
        }
        if self.values.len() == MAX_JVM_MALFORMED_DESCRIPTOR_DIAGNOSTICS {
            let Some(largest) = self.values.last().copied() else {
                return;
            };
            if descriptor >= largest {
                self.truncated = true;
                return;
            }
            self.values.pop_last();
            self.truncated = true;
        }
        self.values.insert(descriptor);
    }

    fn emit(self, diagnostics: &mut BTreeSet<JvmHierarchyDiagnostic>) {
        let mut bytes: usize = 0;
        let mut truncated: bool = self.truncated;
        for descriptor in self.values {
            if bytes.saturating_add(descriptor.len()) > MAX_JVM_MALFORMED_DESCRIPTOR_BYTES {
                truncated = true;
                continue;
            }
            bytes += descriptor.len();
            diagnostics.insert(JvmHierarchyDiagnostic::MalformedDescriptor {
                descriptor: descriptor.to_owned(),
            });
        }
        if truncated {
            diagnostics.insert(JvmHierarchyDiagnostic::MalformedDescriptorDiagnosticLimit {
                max: MAX_JVM_MALFORMED_DESCRIPTOR_DIAGNOSTICS,
                max_bytes: MAX_JVM_MALFORMED_DESCRIPTOR_BYTES,
            });
        }
    }
}

fn enforce_edge_limit(
    graph: &mut BTreeMap<String, JvmHierarchyNode>,
    diagnostics: &mut BTreeSet<JvmHierarchyDiagnostic>,
) {
    let mut remaining: usize = MAX_JVM_HIERARCHY_EDGES;
    for node in graph.values_mut() {
        if node.parents.len() > remaining {
            node.parents.truncate(remaining);
            diagnostics.insert(JvmHierarchyDiagnostic::EdgeLimit {
                max: MAX_JVM_HIERARCHY_EDGES,
            });
        }
        remaining = remaining.saturating_sub(node.parents.len());
    }
}

fn is_type_descriptor(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix('L')
        .and_then(|body: &str| body.strip_suffix(';'))
    else {
        return false;
    };
    !body.is_empty()
        && body.split('/').all(|component: &str| {
            !component.is_empty()
                && component
                    .chars()
                    .all(|character: char| !matches!(character, '.' | ';' | '[' | '/'))
        })
}

fn predecessors<'a>(
    graph: &'a BTreeMap<String, JvmHierarchyNode>,
    target: &'a str,
    diagnostics: &mut BTreeSet<JvmHierarchyDiagnostic>,
) -> BTreeMap<&'a str, &'a str> {
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut edge_count: usize = 0;
    for node in graph.values() {
        for parent in &node.parents {
            if graph.contains_key(parent) {
                if edge_count == MAX_JVM_HIERARCHY_EDGES {
                    diagnostics.insert(JvmHierarchyDiagnostic::EdgeLimit {
                        max: MAX_JVM_HIERARCHY_EDGES,
                    });
                    break;
                }
                edge_count += 1;
                children
                    .entry(parent.as_str())
                    .or_default()
                    .push(node.descriptor.as_str());
            }
        }
    }
    for values in children.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    let mut next: BTreeMap<&str, &str> = BTreeMap::new();
    let mut queue: VecDeque<&str> = VecDeque::from([target]);
    while let Some(parent) = queue.pop_front() {
        for child in children.get(&parent).into_iter().flatten() {
            if *child != target && !next.contains_key(*child) {
                next.insert(*child, parent);
                queue.push_back(child);
            }
        }
    }
    next
}

fn reconstruct_path(
    predecessors: &BTreeMap<&str, &str>,
    start: &str,
    target: &str,
    diagnostics: &mut BTreeSet<JvmHierarchyDiagnostic>,
) -> Option<Vec<String>> {
    let mut path: Vec<String> = vec![start.to_owned()];
    let mut current: &str = start;
    while current != target {
        if path.len() == MAX_JVM_PROOF_DEPTH {
            diagnostics.insert(JvmHierarchyDiagnostic::ProofDepthLimit {
                max: MAX_JVM_PROOF_DEPTH,
            });
            return None;
        }
        let parent: &str = predecessors.get(current)?;
        path.push(parent.to_owned());
        current = parent;
    }
    Some(path)
}

fn cycles(graph: &BTreeMap<String, JvmHierarchyNode>) -> Vec<Vec<String>> {
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut order: Vec<&str> = Vec::with_capacity(graph.len());
    for start in graph.keys() {
        if !visited.insert(start.as_str()) {
            continue;
        }
        let mut stack: Vec<(&str, bool)> = vec![(start.as_str(), false)];
        while let Some((node, expanded)) = stack.pop() {
            if expanded {
                order.push(node);
                continue;
            }
            stack.push((node, true));
            if let Some(item) = graph.get(node) {
                for parent in item.parents.iter().rev() {
                    if graph.contains_key(parent) && visited.insert(parent) {
                        stack.push((parent, false));
                    }
                }
            }
        }
    }
    let mut reverse: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in graph.values() {
        for parent in &node.parents {
            if graph.contains_key(parent) {
                reverse
                    .entry(parent.as_str())
                    .or_default()
                    .push(node.descriptor.as_str());
            }
        }
    }
    let mut assigned: BTreeSet<&str> = BTreeSet::new();
    let mut result: Vec<Vec<String>> = Vec::new();
    for start in order.into_iter().rev() {
        if !assigned.insert(start) {
            continue;
        }
        let mut component: Vec<String> = Vec::new();
        let mut stack: Vec<&str> = vec![start];
        while let Some(node) = stack.pop() {
            component.push(node.to_owned());
            for child in reverse.get(&node).into_iter().flatten().rev() {
                if assigned.insert(child) {
                    stack.push(child);
                }
            }
        }
        component.sort();
        if component.len() > 1 {
            result.push(component);
        }
    }
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_ceiling_applies_before_cycle_detection() {
        let mut graph: BTreeMap<String, JvmHierarchyNode> = BTreeMap::from([(
            "Lexample/Root;".to_owned(),
            JvmHierarchyNode {
                descriptor: "Lexample/Root;".to_owned(),
                kind: JvmTypeKind::Interface,
                parents: (0..=MAX_JVM_HIERARCHY_EDGES)
                    .map(|index: usize| format!("Lexample/P{index};"))
                    .collect(),
            },
        )]);
        let mut diagnostics: BTreeSet<JvmHierarchyDiagnostic> = BTreeSet::new();
        enforce_edge_limit(&mut graph, &mut diagnostics);
        assert_eq!(
            graph["Lexample/Root;"].parents.len(),
            MAX_JVM_HIERARCHY_EDGES
        );
        assert!(diagnostics.contains(&JvmHierarchyDiagnostic::EdgeLimit {
            max: MAX_JVM_HIERARCHY_EDGES,
        }));
    }
}
