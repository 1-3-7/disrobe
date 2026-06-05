#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    RenameStats, ScopeAwareStats, StringArrayRecovery, UnminifyStats, recover_string_array,
    rename_hex_idents, rename_scope_aware, unminify,
};

#[test]
fn full_pipeline_collapses_obfuscator_io_sample() {
    let source: &str = include_str!("../../../corpus/src/javascript/full-pipeline.js");

    let recovery: StringArrayRecovery = recover_string_array(source)
        .expect("string array recovery")
        .expect("must detect string array");
    assert_eq!(recovery.array_id, "_0xabcd");
    assert!(recovery.rotator_removed, "rotator IIFE must be removed");

    let (after_unminify, stats): (String, UnminifyStats) = unminify(&recovery.rewritten_source);
    assert!(
        stats.bool_shorthand_reversed >= 2,
        "!0/!1 reversals: {}",
        stats.bool_shorthand_reversed
    );
    assert!(stats.void_undefined_reversed >= 1, "void 0 reversal");
    assert!(
        stats.arithmetic_folded >= 2,
        "arithmetic folding: {}",
        stats.arithmetic_folded
    );
    assert!(
        stats.globals_evaluated >= 1,
        "atob eval: {}",
        stats.globals_evaluated
    );
    assert!(stats.if_true_inlined >= 1, "if-true inline");
    assert!(stats.if_false_eliminated >= 1, "if-false drop");
    assert!(
        stats.set_interval_watchdogs_removed >= 1,
        "setInterval watchdog"
    );
    assert!(
        stats.control_flow_blocks_unflattened >= 1,
        "control-flow unflatten"
    );
    assert!(
        stats.control_flow_cases_inlined >= 3,
        "switch cases inlined"
    );

    let (after_rename, rename_stats): (String, RenameStats) = rename_hex_idents(&after_unminify);
    assert!(
        rename_stats.idents_renamed >= 3,
        "renamed at least 3 idents; got {}",
        rename_stats.idents_renamed
    );
    assert!(!after_rename.contains("_0xfeed"));
    assert!(!after_rename.contains("_0xdead"));
    assert!(!after_rename.contains("_0xbeef"));

    let (final_source, scope_stats): (String, ScopeAwareStats) =
        rename_scope_aware(&after_rename).expect("scope-aware rename");
    let _ = scope_stats;

    assert!(
        final_source.contains("Hello, world"),
        "decoded literal must survive: {final_source}"
    );
    assert!(final_source.contains("step_a"));
    assert!(final_source.contains("step_b"));
    assert!(final_source.contains("step_c"));
    let pos_c: usize = final_source.find("step_c()").expect("step_c");
    let pos_a: usize = final_source.find("step_a()").expect("step_a");
    let pos_b: usize = final_source.find("step_b()").expect("step_b");
    assert!(
        pos_c < pos_a && pos_a < pos_b,
        "control-flow order must be c,a,b: got positions {pos_c}/{pos_a}/{pos_b}"
    );
    assert!(!final_source.contains("setInterval"));
    assert!(!final_source.contains("debugger"));
    assert!(!final_source.contains("if (false)"));
}
