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
