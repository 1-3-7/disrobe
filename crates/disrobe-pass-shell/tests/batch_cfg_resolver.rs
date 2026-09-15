#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_ir::{DisasmSymbol, DisasmSymbolKind};
use disrobe_pass_shell::{BasicBlock, BatchCfg, CfgEdge, EdgeKind, resolve_cfg};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn read_corpus(relative: &str) -> String {
    let p: PathBuf = corpus_path(relative);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

#[test]
fn megafile_recovers_known_labels() {
    let src: String = read_corpus("batch/megafile/edge_cases.bat");
    let cfg: BatchCfg = resolve_cfg(&src);
    for expected in [
        "MAIN_FLOW",
        "PRINT_BANNER",
        "PARSE_OPTS",
        "PARSE_OPTS_LOOP",
        "KIND_ZIP",
        "KIND_UNKNOWN",
        "LOOP_BREAK_DONE",
        "END_OF_SCRIPT",
    ] {
        assert!(
            cfg.labels.contains_key(expected),
            "label {expected} not recovered; got {:?}",
            cfg.labels.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn megafile_classifies_call_targets_as_functions() {
    let src: String = read_corpus("batch/megafile/edge_cases.bat");
    let cfg: BatchCfg = resolve_cfg(&src);
    for callee in ["PRINT_BANNER", "ECHO_THREE", "SUM_TWO", "PARSE_OPTS"] {
        assert!(
            cfg.call_targets.iter().any(|t: &String| t == callee),
            "expected {callee} among call targets; got {:?}",
            cfg.call_targets
        );
    }
    let symbols: Vec<DisasmSymbol> = cfg.to_ir_symbols();
    let print_banner: &DisasmSymbol = symbols
        .iter()
        .find(|s: &&DisasmSymbol| s.name == "PRINT_BANNER")
        .expect("PRINT_BANNER symbol");
    assert_eq!(
        print_banner.kind,
        DisasmSymbolKind::Function,
        "called label must lower to IR Function"
    );
    let goto_only: &DisasmSymbol = symbols
        .iter()
        .find(|s: &&DisasmSymbol| s.name == "KIND_ZIP")
        .expect("KIND_ZIP symbol");
    assert_eq!(
        goto_only.kind,
        DisasmSymbolKind::Label,
        "goto-only label must lower to IR Label"
    );
}

#[test]
fn megafile_resolves_goto_edges_to_existing_blocks() {
    let src: String = read_corpus("batch/megafile/edge_cases.bat");
    let cfg: BatchCfg = resolve_cfg(&src);
    let resolved_gotos: usize = cfg
        .blocks
        .iter()
        .flat_map(|b: &BasicBlock| &b.edges)
        .filter(|e: &&CfgEdge| {
            matches!(e.kind, EdgeKind::Goto | EdgeKind::ConditionalGoto) && e.target_block.is_some()
        })
        .count();
    assert!(
        resolved_gotos >= 3,
        "expected several goto edges to resolve to real blocks, got {resolved_gotos}"
    );
}

#[test]
fn megafile_surfaces_computed_switch_dispatch_as_unresolved() {
    let src: String = read_corpus("batch/megafile/edge_cases.bat");
    let cfg: BatchCfg = resolve_cfg(&src);
    assert!(
        cfg.unresolved_targets
            .iter()
            .any(|t: &String| t.contains('%')),
        "computed `call :SWITCH_FRUIT_%FRUIT%` must surface as unresolved; got {:?}",
        cfg.unresolved_targets
    );
}

#[test]
fn parse_opts_loop_back_edge_resolves() {
    let src: String = read_corpus("batch/megafile/edge_cases.bat");
    let cfg: BatchCfg = resolve_cfg(&src);
    let loop_target: usize = *cfg
        .labels
        .get("PARSE_OPTS_LOOP")
        .expect("PARSE_OPTS_LOOP label");
    let has_back_edge: bool =
        cfg.blocks
            .iter()
            .flat_map(|b: &BasicBlock| &b.edges)
            .any(|e: &CfgEdge| {
                e.target_label.as_deref() == Some("PARSE_OPTS_LOOP")
                    && e.target_block == Some(loop_target)
            });
    assert!(
        has_back_edge,
        "the option-parsing loop's `goto :PARSE_OPTS_LOOP` back-edge must resolve"
    );
}
