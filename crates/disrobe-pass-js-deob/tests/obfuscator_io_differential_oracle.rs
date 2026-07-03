#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    ObfuscatorIoOptions, ObfuscatorIoOutput, ObfuscatorIoPreset, obfuscator_io_deobfuscate,
    obfuscator_io_deobfuscate_preset,
};

fn corpus_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("src")
        .join("javascript")
        .join("obfuscator-io-samples")
}

fn clean_source() -> Option<String> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p: PathBuf = manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("src")
        .join("javascript")
        .join("obfuscator-io-high.js");
    fs::read_to_string(p).ok()
}

fn read_preset(name: &str) -> Option<String> {
    let p: PathBuf = corpus_root().join("presets").join(format!("{name}.js"));
    fs::read_to_string(p).ok()
}

fn read_control(name: &str) -> Option<String> {
    let p: PathBuf = corpus_root().join("controls").join(format!("{name}.js"));
    fs::read_to_string(p).ok()
}

fn clean_tokens(clean: &str) -> BTreeSet<String> {
    let idents: BTreeSet<String> = [
        "add",
        "subtract",
        "multiply",
        "divide",
        "calculate",
        "greet",
        "runSamples",
        "Error",
        "console",
        "switch",
        "throw",
        "return",
        "function",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let strings: BTreeSet<String> = [
        "divide by zero",
        "unknown op",
        "calculator ready",
        "hello,",
        "add",
        "sub",
        "mul",
        "div",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let _ = clean;
    idents.union(&strings).cloned().collect()
}

fn recovery_rate(deob: &str, tokens: &BTreeSet<String>) -> (usize, usize) {
    let mut hits: usize = 0;
    for tok in tokens {
        if deob.contains(tok.as_str()) {
            hits += 1;
        }
    }
    (hits, tokens.len())
}

fn run_full(src: &str) -> ObfuscatorIoOutput {
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    obfuscator_io_deobfuscate(src, &opts).expect("deob ok")
}

#[test]
fn differential_oracle_reports_recovery_rate() {
    let Some(clean): Option<String> = clean_source() else {
        return;
    };
    let tokens: BTreeSet<String> = clean_tokens(&clean);

    let mut total_hits: usize = 0;
    let mut total_possible: usize = 0;
    let mut inline_total: usize = 0;

    for preset_name in ["low", "medium", "high"] {
        let Some(src): Option<String> = read_preset(preset_name) else {
            continue;
        };
        let out: ObfuscatorIoOutput = run_full(&src);
        let (hits, possible): (usize, usize) = recovery_rate(&out.source, &tokens);
        inline_total += out.string_array_call_sites_inlined;
        total_hits += hits;
        total_possible += possible;
        let pct: f64 = (hits as f64 / possible as f64) * 100.0;
        println!(
            "[preset:{preset_name}] tokens {hits}/{possible} = {pct:.1}% | inlined={} cfo_merged={} cff_collapsed={} dispatcher={} opaque={}",
            out.string_array_call_sites_inlined,
            out.control_flow_objects_merged,
            out.flatten_dispatches_collapsed,
            out.dispatcher_call_sites_inlined,
            out.opaque_predicates_folded,
        );
    }

    for control_name in [
        "controlFlowFlattening",
        "objectTransform",
        "stringArrayRotate",
    ] {
        let Some(src): Option<String> = read_control(control_name) else {
            continue;
        };
        let out: ObfuscatorIoOutput = run_full(&src);
        let (hits, possible): (usize, usize) = recovery_rate(&out.source, &tokens);
        total_hits += hits;
        total_possible += possible;
        let pct: f64 = (hits as f64 / possible as f64) * 100.0;
        println!(
            "[control:{control_name}] tokens {hits}/{possible} = {pct:.1}% | cfo_merged={} cff_collapsed={}",
            out.control_flow_objects_merged, out.flatten_dispatches_collapsed,
        );
    }

    if total_possible == 0 {
        return;
    }
    let overall: f64 = (total_hits as f64 / total_possible as f64) * 100.0;
    println!(
        "[OVERALL] {total_hits}/{total_possible} = {overall:.1}% | total_inlined={inline_total}"
    );
}

fn count_residual_decoder_calls(source: &str) -> usize {
    let re: regex::Regex =
        regex::Regex::new(r"[A-Za-z_$][\w$]*\(\s*0x[0-9a-fA-F]+\s*[,)]").expect("re");
    re.find_iter(source).count()
}

#[test]
fn high_preset_recovers_operator_semantics_via_cfo() {
    let Some(src): Option<String> = read_preset("high") else {
        return;
    };
    let out: ObfuscatorIoOutput = run_full(&src);
    assert!(
        out.control_flow_objects_merged > 0,
        "high preset must merge control-flow objects; got {}",
        out.control_flow_objects_merged
    );
    let recovered_ops: bool = out.source.contains("return (var")
        && ["+", "-", "*", "/"]
            .iter()
            .all(|op: &&str| out.source.contains(*op));
    assert!(
        recovered_ops,
        "expected merged arithmetic operators inline in recovered function bodies"
    );
    assert!(
        out.source.contains("'divide by zero'") || out.source.contains("divide by zero"),
        "throw-string must survive cfo merge"
    );
}

#[test]
fn cfo_recovers_operator_semantics_on_medium() {
    let Some(src): Option<String> = read_preset("medium") else {
        return;
    };
    let with_cfo: ObfuscatorIoOutput = run_full(&src);
    assert!(
        with_cfo.control_flow_objects_merged > 0,
        "cfo must merge at least one object on medium"
    );
    assert!(
        with_cfo.source.contains("return var")
            && (with_cfo.source.contains("+var") || with_cfo.source.contains("+ var")),
        "merged arithmetic must appear inline in recovered function bodies"
    );
}

#[test]
fn decoder_inline_rate_is_high_on_presets() {
    for name in ["low", "medium", "high"] {
        let Some(src): Option<String> = read_preset(name) else {
            continue;
        };
        let before: usize = count_residual_decoder_calls(&src);
        if before == 0 {
            continue;
        }
        let out: ObfuscatorIoOutput = run_full(&src);
        let after: usize = count_residual_decoder_calls(&out.source);
        let inline_rate: f64 = 1.0 - (after as f64 / before as f64);
        assert!(
            inline_rate >= 0.92,
            "{name}: decoder-call inline rate must be >=92%; before={before} after={after} rate={inline_rate:.3}"
        );
    }
}

#[test]
fn high_preset_recovers_clean_tokens_above_threshold() {
    let Some(clean): Option<String> = clean_source() else {
        return;
    };
    let Some(src): Option<String> = read_preset("high") else {
        return;
    };
    let tokens: BTreeSet<String> = clean_tokens(&clean);
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(&src, ObfuscatorIoPreset::High).expect("ok");
    let (hits, possible): (usize, usize) = recovery_rate(&out.source, &tokens);
    let pct: f64 = (hits as f64 / possible as f64) * 100.0;
    assert!(
        pct >= 92.0,
        "high preset clean-token recovery must be >=92%, got {pct:.1}% ({hits}/{possible})\nhead=\n{}",
        &out.source[..out.source.len().min(2000)]
    );
}

fn balanced(source: &str) -> bool {
    let (mut paren, mut brace, mut bracket): (i64, i64, i64) = (0, 0, 0);
    let mut in_str: Option<char> = None;
    let mut escaped: bool = false;
    for c in source.chars() {
        if let Some(q) = in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                in_str = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => in_str = Some(c),
            '(' => paren += 1,
            ')' => paren -= 1,
            '{' => brace += 1,
            '}' => brace -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            _ => {}
        }
    }
    paren == 0 && brace == 0 && bracket == 0
}

#[test]
fn scope_proxy_merges_iife_objects_without_corruption() {
    let Some(src): Option<String> = read_preset("high") else {
        return;
    };
    let out: ObfuscatorIoOutput = run_full(&src);
    assert!(
        out.scope_proxy_objects_merged >= 2,
        "scope-aware proxy merge must clear several self-defending-IIFE objects the regex pass guards out; got {}",
        out.scope_proxy_objects_merged
    );
    assert!(
        out.control_flow_objects_merged + out.scope_proxy_objects_merged >= 5,
        "combined regex+scope-proxy merge must resolve at least 5 proxy objects total; got cf={} scope={}",
        out.control_flow_objects_merged,
        out.scope_proxy_objects_merged
    );
    assert!(
        balanced(&out.source),
        "merged output must keep delimiters balanced (no IIFE corruption)"
    );
    assert!(
        out.source.contains("'divide by zero'") || out.source.contains("divide by zero"),
        "real strings must survive the scope merge"
    );
}
