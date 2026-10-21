#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_pass_jvm::{DexCallGraph, DexCallGraphEdge, DexCallGraphNode, dex_call_graph};

fn fixture(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit");
    path.push(rel);
    path
}

fn read(rel: &str) -> Vec<u8> {
    let path: PathBuf = fixture(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn normalise_label(label: &str) -> String {
    let signature: &str = label.split(" [access_flags=").next().unwrap_or(label);
    signature.replace(' ', "")
}

fn gml_edges(text: &str) -> BTreeSet<(String, String)> {
    let mut labels: BTreeMap<u64, String> = BTreeMap::new();
    let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
    let mut current_id: Option<u64> = None;
    let mut source: Option<u64> = None;
    for raw in text.lines() {
        let line: &str = raw.trim();
        if let Some(id) = line.strip_prefix("id ") {
            current_id = Some(id.trim().parse().expect("node id"));
        } else if let Some(label) = line.strip_prefix("label ") {
            let label: &str = label.trim().trim_matches('"');
            let id: u64 = current_id.expect("label after id");
            labels.insert(id, normalise_label(label));
        } else if let Some(from) = line.strip_prefix("source ") {
            source = Some(from.trim().parse().expect("edge source"));
        } else if let Some(to) = line.strip_prefix("target ") {
            let from: u64 = source.take().expect("target after source");
            let to: u64 = to.trim().parse().expect("edge target");
            edges.insert((labels[&from].clone(), labels[&to].clone()));
        }
    }
    edges
}

fn disrobe_edges(graph: &DexCallGraph) -> BTreeSet<(String, String)> {
    graph
        .edges
        .iter()
        .map(|edge: &DexCallGraphEdge| (edge.caller.clone(), edge.callee.clone()))
        .collect()
}

#[test]
fn plants_call_edges_equal_androguard() {
    let graph: DexCallGraph = dex_call_graph(&read("audit-plants.apk")).expect("call graph");
    let reference_text: String =
        std::fs::read_to_string(fixture("reference/plants.androguard-cg.gml"))
            .expect("androguard call graph");
    let reference: BTreeSet<(String, String)> = gml_edges(&reference_text);
    assert_eq!(reference.len(), 77, "androguard cg on the plants APK");
    assert_eq!(
        disrobe_edges(&graph),
        reference,
        "every caller to callee pair equals androguard's cg output"
    );
    assert!(!graph.truncated);
    assert_eq!(graph.dex_files, 1);
    let endpoints: BTreeSet<&str> = graph
        .edges
        .iter()
        .flat_map(|e: &DexCallGraphEdge| [e.caller.as_str(), e.callee.as_str()])
        .collect();
    let nodes: BTreeSet<&str> = graph
        .nodes
        .iter()
        .map(|n: &DexCallGraphNode| n.method.as_str())
        .collect();
    assert!(endpoints.is_subset(&nodes), "every edge endpoint is a node");
    let external: usize = graph
        .nodes
        .iter()
        .filter(|n: &&DexCallGraphNode| n.external)
        .count();
    assert_eq!(external, 57, "androguard marks 57 callee nodes external");
}

#[test]
fn call_sites_are_counted_per_edge_and_the_control_apk_has_fewer_edges() {
    let plants: DexCallGraph = dex_call_graph(&read("audit-plants.apk")).expect("plants");
    let control: DexCallGraph = dex_call_graph(&read("audit-control.apk")).expect("control");
    assert!(plants.edges.len() > control.edges.len());
    assert!(
        plants
            .edges
            .iter()
            .all(|e: &DexCallGraphEdge| e.call_sites >= 1),
        "{:#?}",
        plants.edges
    );
    let dot: String = plants.to_dot();
    assert!(dot.starts_with("digraph calls {"));
    assert!(dot.contains("Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;"));
}

#[test]
fn one_dropped_reference_edge_turns_the_comparison_red() {
    let text: String = std::fs::read_to_string(fixture("reference/plants.androguard-cg.gml"))
        .expect("androguard call graph");
    let full: BTreeSet<(String, String)> = gml_edges(&text);
    let marker: &str = "  edge [";
    let first: usize = text.find(marker).expect("an edge");
    let second: usize = text[first + marker.len()..]
        .find(marker)
        .map(|at: usize| at + first + marker.len())
        .expect("a second edge");
    let mutated: String = format!("{}{}", &text[..first], &text[second..]);
    assert_ne!(text, mutated);
    assert_eq!(gml_edges(&mutated).len(), full.len() - 1);
}
