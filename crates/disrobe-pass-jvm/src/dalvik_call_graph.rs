use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::dalvik::{DalvikInsn, decode_method};
use crate::dalvik_interp::method_descriptor;
use crate::dex::{CodeItem, DexFile, MethodId, parse as parse_dex, parse_code_items};
use crate::error::Result;
use crate::jar::{ApkExtract, extract_apk};

const MAX_CALL_GRAPH_EDGES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DexCallGraphNode {
    pub method: String,
    pub external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DexCallGraphEdge {
    pub caller: String,
    pub callee: String,
    pub call_sites: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexCallGraph {
    pub dex_files: usize,
    pub nodes: Vec<DexCallGraphNode>,
    pub edges: Vec<DexCallGraphEdge>,
    pub truncated: bool,
}

impl DexCallGraph {
    #[must_use]
    pub fn to_dot(&self) -> String {
        use std::fmt::Write as _;
        let mut out: String = String::from("digraph calls {\n  rankdir=LR;\n");
        for node in &self.nodes {
            let shape: &str = if node.external { "ellipse" } else { "box" };
            let _ = writeln!(
                out,
                "  \"{}\" [shape={shape}];",
                node.method.replace('"', "\\\"")
            );
        }
        for edge in &self.edges {
            let _ = writeln!(
                out,
                "  \"{}\" -> \"{}\" [label=\"{}\"];",
                edge.caller.replace('"', "\\\""),
                edge.callee.replace('"', "\\\""),
                edge.call_sites
            );
        }
        out.push_str("}\n");
        out
    }
}

fn signature(method: &MethodId) -> String {
    format!(
        "{}->{}{}",
        method.class,
        method.name,
        method_descriptor(method)
    )
}

fn graph_dex_into(dex: &DexFile, bytes: &[u8], graph: &mut DexCallGraph) {
    let code = parse_code_items(dex, bytes);
    let classes: BTreeSet<&str> = dex.class_descriptors.iter().map(String::as_str).collect();
    let defined: BTreeSet<String> = dex
        .method_ids
        .iter()
        .filter(|m: &&MethodId| classes.contains(m.class.as_str()))
        .map(signature)
        .collect();
    let mut edges: BTreeMap<(String, String), usize> = graph
        .edges
        .drain(..)
        .map(|edge: DexCallGraphEdge| ((edge.caller, edge.callee), edge.call_sites))
        .collect();
    let mut nodes: BTreeMap<String, bool> = graph
        .nodes
        .drain(..)
        .map(|node: DexCallGraphNode| (node.method, node.external))
        .collect();
    for item in code.decoded() {
        let item: &CodeItem = item;
        let caller: String = format!(
            "{}->{}{}",
            item.class, item.method_name, item.method_descriptor
        );
        nodes.insert(caller.clone(), false);
        let insns: Vec<DalvikInsn> = decode_method(&item.insns);
        for insn in &insns {
            if !matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78) {
                continue;
            }
            let Some(callee) = insn
                .index
                .and_then(|i: u32| dex.method_ids.get(usize::try_from(i).ok()?))
            else {
                continue;
            };
            let callee_sig: String = signature(callee);
            if edges.len() >= MAX_CALL_GRAPH_EDGES
                && !edges.contains_key(&(caller.clone(), callee_sig.clone()))
            {
                graph.truncated = true;
                continue;
            }
            nodes
                .entry(callee_sig.clone())
                .or_insert_with(|| !defined.contains(&callee_sig));
            *edges.entry((caller.clone(), callee_sig)).or_insert(0) += 1;
        }
    }
    graph.nodes = nodes
        .into_iter()
        .map(|(method, external): (String, bool)| DexCallGraphNode { method, external })
        .collect();
    graph.edges = edges
        .into_iter()
        .map(
            |((caller, callee), call_sites): ((String, String), usize)| DexCallGraphEdge {
                caller,
                callee,
                call_sites,
            },
        )
        .collect();
}

pub fn dex_call_graph(bytes: &[u8]) -> Result<DexCallGraph> {
    let mut graph: DexCallGraph = DexCallGraph::default();
    if bytes.len() >= 4 && bytes[..4] == [0x50, 0x4B, 0x03, 0x04] {
        let extract: ApkExtract = extract_apk(bytes)?;
        for raw in extract.dex_files.values() {
            let dex: DexFile = parse_dex(raw)?;
            graph.dex_files = graph.dex_files.saturating_add(1);
            graph_dex_into(&dex, raw, &mut graph);
        }
        return Ok(graph);
    }
    let dex: DexFile = parse_dex(bytes)?;
    graph.dex_files = 1;
    graph_dex_into(&dex, bytes, &mut graph);
    Ok(graph)
}

const MAX_PAIR_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPair {
    pub source: &'static str,
    pub sink: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ApiPairHit {
    pub entry: String,
    pub source: String,
    pub sink: String,
    pub source_depth: usize,
    pub sink_depth: usize,
}

fn api_matches(method: &str, api: &str) -> bool {
    method
        .split_once('(')
        .is_some_and(|(head, _): (&str, &str)| head == api)
}

fn reachable_externals(
    graph: &DexCallGraph,
    callees: &BTreeMap<&str, Vec<&str>>,
    external: &BTreeSet<&str>,
    entry: &str,
) -> BTreeMap<String, usize> {
    let mut depth_of: BTreeMap<&str, usize> = BTreeMap::new();
    let mut frontier: Vec<(&str, usize)> = vec![(entry, 0)];
    depth_of.insert(entry, 0);
    while let Some((method, depth)) = frontier.pop() {
        if depth >= MAX_PAIR_DEPTH {
            continue;
        }
        for &callee in callees.get(method).map(Vec::as_slice).unwrap_or_default() {
            if depth_of.contains_key(callee) {
                continue;
            }
            depth_of.insert(callee, depth + 1);
            if !external.contains(callee) {
                frontier.push((callee, depth + 1));
            }
        }
    }
    let _ = graph;
    depth_of
        .into_iter()
        .filter(|(method, _): &(&str, usize)| external.contains(method))
        .map(|(method, depth): (&str, usize)| (method.to_owned(), depth))
        .collect()
}

#[must_use]
pub fn reachable_api_pairs(graph: &DexCallGraph, pairs: &[ApiPair]) -> Vec<ApiPairHit> {
    let external: BTreeSet<&str> = graph
        .nodes
        .iter()
        .filter(|node: &&DexCallGraphNode| node.external)
        .map(|node: &DexCallGraphNode| node.method.as_str())
        .collect();
    let mut callees: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &graph.edges {
        callees
            .entry(edge.caller.as_str())
            .or_default()
            .push(edge.callee.as_str());
    }
    let mut reach: BTreeMap<&str, BTreeMap<String, usize>> = BTreeMap::new();
    for node in &graph.nodes {
        if node.external {
            continue;
        }
        reach.insert(
            node.method.as_str(),
            reachable_externals(graph, &callees, &external, &node.method),
        );
    }
    let mut hits: Vec<ApiPairHit> = Vec::new();
    for (entry, externals) in &reach {
        for pair in pairs {
            let sources: Vec<(&String, &usize)> = externals
                .iter()
                .filter(|(method, _): &(&String, &usize)| api_matches(method, pair.source))
                .collect();
            let sinks: Vec<(&String, &usize)> = externals
                .iter()
                .filter(|(method, _): &(&String, &usize)| api_matches(method, pair.sink))
                .collect();
            if sources.is_empty() || sinks.is_empty() {
                continue;
            }
            let innermost: bool = callees
                .get(entry)
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .filter(|callee: &&&str| !external.contains(**callee))
                .all(|callee: &&str| {
                    reach
                        .get(*callee)
                        .is_none_or(|below: &BTreeMap<String, usize>| {
                            !(below.keys().any(|m: &String| api_matches(m, pair.source))
                                && below.keys().any(|m: &String| api_matches(m, pair.sink)))
                        })
                });
            if !innermost {
                continue;
            }
            for (source, source_depth) in &sources {
                for (sink, sink_depth) in &sinks {
                    hits.push(ApiPairHit {
                        entry: (*entry).to_owned(),
                        source: (*source).clone(),
                        sink: (*sink).clone(),
                        source_depth: **source_depth,
                        sink_depth: **sink_depth,
                    });
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}
