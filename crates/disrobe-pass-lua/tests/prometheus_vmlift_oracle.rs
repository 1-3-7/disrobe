#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_lua::prometheus_vmlift;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn corpus_path(rel: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

fn load(rel: &str) -> String {
    let path: PathBuf = corpus_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()))
}

fn find_lua() -> Option<String> {
    let candidates: [&str; 6] = ["lua", "lua5.4", "lua5.1", "luajit", "lua54", "lua51"];
    for c in candidates {
        if Command::new(c)
            .arg("-v")
            .output()
            .is_ok_and(|o| o.status.success() || !o.stderr.is_empty())
        {
            return Some(c.to_owned());
        }
    }
    None
}

fn run_lua(interp: &str, source: &str) -> Option<String> {
    let unique: u64 = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp: PathBuf =
        std::env::temp_dir().join(format!("prom_vmlift_{}_{unique}.lua", std::process::id()));
    fs::write(&tmp, source).ok()?;
    let out = Command::new(interp).arg(&tmp).output().ok()?;
    let _ = fs::remove_file(&tmp);
    if !out.status.success() {
        eprintln!("lua run failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
}

fn fold_preserves_behavior(rel: &str) -> (usize, usize) {
    let Some(interp): Option<String> = find_lua() else {
        eprintln!("no lua interpreter on PATH; skipping fold oracle for {rel}");
        return (0, 0);
    };
    let obf: String = load(rel);
    let expected: String = run_lua(&interp, &obf)
        .unwrap_or_else(|| panic!("real obfuscated {rel} failed to run under {interp}"));

    let before: usize = prometheus_vmlift::count_arithmetic_operators(&obf);
    let folded: String = prometheus_vmlift::fold_numeric_expressions(&obf);
    let after: usize = prometheus_vmlift::count_arithmetic_operators(&folded);

    let actual: String = run_lua(&interp, &folded)
        .unwrap_or_else(|| panic!("folded {rel} failed to run under {interp} (semantics broke)"));

    assert_eq!(
        actual.trim_end(),
        expected.trim_end(),
        "{rel}: numeric-expression fold must preserve runtime stdout exactly"
    );
    eprintln!(
        "fold oracle {rel}: OK stdout={:?} arithmetic-ops {before} -> {after}",
        expected.trim_end()
    );
    (before, after)
}

#[test]
fn fold_reconstruction_preserves_inter_span_text() {
    for rel in [
        "obfuscators/hello.prometheus.lua",
        "obfuscators/edge_cases.prometheus_weak.lua",
        "prometheus/gauntlet/gauntlet_weak_obfuscated.lua",
    ] {
        let obf: String = load(rel);
        let offsets: Vec<(usize, usize, String)> = prometheus_vmlift::folded_span_offsets(&obf);
        let folded: String = prometheus_vmlift::fold_numeric_expressions(&obf);
        let mut rebuilt: String = String::with_capacity(folded.len());
        let mut cursor: usize = 0;
        let mut prev_end: usize = 0;
        for (start, end, value) in &offsets {
            assert!(
                *start >= prev_end,
                "{rel}: fold spans must not overlap ({prev_end} > {start})"
            );
            rebuilt.push_str(&obf[cursor..*start]);
            rebuilt.push_str(value);
            cursor = *end;
            prev_end = *end;
        }
        rebuilt.push_str(&obf[cursor..]);
        let strip_ws = |s: &str| -> String {
            s.chars()
                .filter(|c: &char| !c.is_ascii_whitespace())
                .collect()
        };
        assert_eq!(
            strip_ws(&rebuilt),
            strip_ws(&folded),
            "{rel}: fold output must equal original-text + folded-values (ignoring guard whitespace)"
        );
        eprintln!("{rel}: {} spans, inter-span text preserved", offsets.len());
    }
}

#[test]
fn every_folded_span_matches_lua_evaluation() {
    let Some(interp): Option<String> = find_lua() else {
        eprintln!("no lua interpreter; skipping per-span fold verification");
        return;
    };
    for rel in [
        "obfuscators/hello.prometheus.lua",
        "obfuscators/edge_cases.prometheus_weak.lua",
        "prometheus/gauntlet/gauntlet_weak_obfuscated.lua",
    ] {
        let obf: String = load(rel);
        let pairs: Vec<(String, String)> = prometheus_vmlift::folded_span_pairs(&obf);
        if pairs.is_empty() {
            eprintln!("{rel}: no NumbersToExpressions layer present (nothing to fold)");
            continue;
        }
        let mut prog: String = String::new();
        for (idx, (orig, folded)) in pairs.iter().enumerate() {
            let _ = writeln!(
                prog,
                "do local a={folded} local b=({orig}) if a~=b then print({idx},a,b) end end"
            );
        }
        let out: String =
            run_lua(&interp, &prog).unwrap_or_else(|| panic!("{rel}: span check program failed"));
        assert!(
            out.trim().is_empty(),
            "{rel}: {} folded spans disagree with Lua evaluation:\n{out}",
            out.lines().count()
        );
        eprintln!("{rel}: all {} folded spans match Lua exactly", pairs.len());
    }
}

#[test]
fn fold_hello_strips_numbers_to_expressions_layer() {
    if find_lua().is_none() {
        return;
    }
    let (before, after): (usize, usize) =
        fold_preserves_behavior("obfuscators/hello.prometheus.lua");
    assert!(
        before > 800,
        "hello carries the NumbersToExpressions layer; expected >800 arithmetic ops, got {before}"
    );
    assert!(
        after * 2 < before,
        "fold must remove the majority of the NumbersToExpressions layer ({before} -> {after})"
    );
}

#[test]
fn fold_weak_preserves_runtime_output() {
    let _ = fold_preserves_behavior("obfuscators/edge_cases.prometheus_weak.lua");
}

#[test]
fn fold_gauntlet_weak_preserves_runtime_output() {
    let _ = fold_preserves_behavior("prometheus/gauntlet/gauntlet_weak_obfuscated.lua");
}

#[test]
fn fold_minify_preserves_runtime_output() {
    let _ = fold_preserves_behavior("obfuscators/edge_cases.prometheus_minify.lua");
}

#[test]
fn peel_path_applies_fold_and_dispatch_recovery() {
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};
    use disrobe_pass_lua::prometheus;

    let obf: String = load("obfuscators/hello.prometheus.lua");
    let out: PeelResult =
        prometheus::peel(obf.as_bytes(), &DeobfOptions::default()).expect("peel hello");

    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-numbers-to-expressions-fold"),
        "peel must run the numeric fold; passes={:?}",
        out.passes_run
    );
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-vmify-dispatch-cfg-recovery"),
        "peel must recover the dispatch CFG; passes={:?}",
        out.passes_run
    );
    assert!(
        !out.fully_recovered,
        "per-block ops are not re-emitted; must not claim full recovery"
    );

    let deob: &str = std::str::from_utf8(&out.deobfuscated).expect("recovered output is utf8");
    assert!(
        deob.contains("PROMETHEUS_STRINGS") && !deob.trim_start().starts_with("return(function"),
        "peel must emit the decoded constant-array string pool as the recovered artifact (its NumbersToExpressions fold is proven runtime-equivalent by the fold oracle), not the raw VM wrapper; got {:?}",
        deob.chars().take(80).collect::<String>(),
    );
}

#[test]
fn dispatch_cfg_recovered_on_real_vmify_samples() {
    for rel in [
        "obfuscators/hello.prometheus.lua",
        "obfuscators/edge_cases.prometheus_weak.lua",
        "prometheus/gauntlet/gauntlet_weak_obfuscated.lua",
    ] {
        let obf: String = load(rel);
        let folded: String = prometheus_vmlift::fold_numeric_expressions(&obf);
        let report: prometheus_vmlift::DispatchReport =
            prometheus_vmlift::analyze_dispatch(&folded)
                .unwrap_or_else(|| panic!("{rel}: must recover the Vmify dispatch state machine"));
        assert!(
            report.comparison_count >= 10,
            "{rel}: a Vmify dispatch tree must have many state comparisons, got {}",
            report.comparison_count
        );
        assert!(
            report.block_count() >= 5,
            "{rel}: must recover distinct constant leaf states, got {}",
            report.block_count()
        );
        assert!(
            report.successor_edges >= report.block_count(),
            "{rel}: edges {} must be >= blocks {}",
            report.successor_edges,
            report.block_count()
        );
        eprintln!(
            "{rel}: dispatch state-var '{}' comparisons={} leaf-states={} edges={} conditional={}",
            report.state_variable,
            report.comparison_count,
            report.block_count(),
            report.successor_edges,
            report.conditional_blocks
        );
    }
}
