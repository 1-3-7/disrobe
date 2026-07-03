#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_js_deob::{DeobOptions, DeobOutput, deobfuscate_all};

fn recovery_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join("jsconfuser")
        .join("recovery")
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn unique_temp() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "disrobe_jsc_oracle_{}_{seq}.js",
        std::process::id()
    ))
}

fn run_node(code: &str) -> Option<String> {
    run_node_with_args(code, &[])
}

fn run_node_with_args(code: &str, args: &[&str]) -> Option<String> {
    let tmp: PathBuf = unique_temp();
    {
        let mut f: fs::File = fs::File::create(&tmp).ok()?;
        f.write_all(code.as_bytes()).ok()?;
    }
    let output: std::process::Output = Command::new("node")
        .arg("--")
        .arg(&tmp)
        .args(args)
        .output()
        .ok()?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn load_expectations() -> Option<BTreeMap<String, String>> {
    let path: PathBuf = recovery_dir().join("expected.json");
    let raw: String = fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let obj: &serde_json::Map<String, serde_json::Value> = value.as_object()?;
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (key, val) in obj {
        out.insert(key.clone(), val.as_str()?.to_owned());
    }
    Some(out)
}

fn grade(sample_file: &str, removed_markers: &[&str], recovery_signal: fn(&DeobOutput) -> usize) {
    if !node_available() {
        return;
    }
    let expectations: BTreeMap<String, String> =
        load_expectations().expect("expected.json must load");
    let want: &String = expectations
        .get(sample_file)
        .unwrap_or_else(|| panic!("no expectation recorded for {sample_file}"));

    let obf_path: PathBuf = recovery_dir().join(sample_file);
    let obf_src: String =
        fs::read_to_string(&obf_path).unwrap_or_else(|_| panic!("read {sample_file}"));

    let obf_runs: String = run_node(&obf_src)
        .unwrap_or_else(|| panic!("obfuscated sample {sample_file} must execute under node"));
    assert_eq!(
        &obf_runs, want,
        "corpus drift: obfuscated {sample_file} no longer matches recorded expectation"
    );

    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);

    assert!(
        recovery_signal(&out) > 0,
        "deob of {sample_file} must report real recovery work, not a no-op pass-through",
    );
    for marker in removed_markers {
        assert!(
            !out.source.contains(marker),
            "deob of {sample_file} must eliminate the obfuscation marker {marker:?}; behavioral identity alone is not enough since the obfuscated form already runs:\n{}",
            out.source
        );
    }

    let recovered_runs: String = run_node(&out.source).unwrap_or_else(|| {
        panic!(
            "recovered {sample_file} must still execute under node; recovered:\n{}",
            out.source
        )
    });
    assert_eq!(
        &recovered_runs, want,
        "behavioral divergence after deob of {sample_file}\nrecovered source:\n{}",
        out.source
    );
}

#[test]
fn state_sum_cff_recovered_behavior_matches_node() {
    grade(
        "obf_statesum.spec.js",
        &["s0 + s1 + s2", "t0 + t1", "switch ("],
        |out: &DeobOutput| out.state_sum_machines_linearized,
    );
}

#[test]
fn state_sum_cff_dispatcher_is_actually_collapsed() {
    if !node_available() {
        return;
    }
    let obf_path: PathBuf = recovery_dir().join("obf_statesum.spec.js");
    let obf_src: String = fs::read_to_string(&obf_path).expect("read state-sum sample");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);
    assert!(
        out.state_sum_machines_linearized >= 2,
        "both state-sum machines must be linearized; got {}",
        out.state_sum_machines_linearized
    );
    assert!(
        !out.source.contains("s0 + s1 + s2") && !out.source.contains("t0 + t1"),
        "the state-sum dispatch predicate must be gone:\n{}",
        out.source
    );
}

#[test]
fn string_conceal_pool_recovered_behavior_matches_node() {
    grade("obf_checksum.stringconceal.js", &[], |out: &DeobOutput| {
        out.string_conceal_call_sites_decoded
    });
}

#[test]
fn string_conceal_literals_actually_decoded() {
    if !node_available() {
        return;
    }
    let obf_path: PathBuf = recovery_dir().join("obf_checksum.stringconceal.js");
    let obf_src: String = fs::read_to_string(&obf_path).expect("read string-conceal sample");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);
    assert!(
        out.string_conceal_call_sites_decoded > 0,
        "the concealed string pool must be decoded at the call sites; got {}",
        out.string_conceal_call_sites_decoded
    );
    assert!(
        out.source.contains("\"forensic\"") || out.source.contains("'forensic'"),
        "a known plaintext from the source must reappear as a decoded literal:\n{}",
        out.source
    );
}

#[test]
fn string_compression_pool_recovered_behavior_matches_node() {
    grade(
        "obf_stringcompression.real.js",
        &["[\"decompressFromUTF16\"](compressedString)"],
        |out: &DeobOutput| out.string_compression_blocks_reversed,
    );
}

#[test]
fn string_compression_literals_actually_decoded() {
    if !node_available() {
        return;
    }
    let obf_path: PathBuf = recovery_dir().join("obf_stringcompression.real.js");
    let obf_src: String = fs::read_to_string(&obf_path).expect("read string-compression sample");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);
    assert!(
        out.string_compression_blocks_reversed > 0,
        "the compressed LZString pool must be decoded; got {}",
        out.string_compression_blocks_reversed
    );
    assert!(
        out.source.contains("forensic marker lzstring"),
        "a known plaintext from the source must reappear in the recovered string pool:\n{}",
        out.source
    );
}

#[test]
fn rgf_eval_wrappers_recovered_behavior_matches_node() {
    grade(
        "obf_tokenizer.rgf.js",
        &["_rgf_eval(", "rgf_eval_integrity"],
        |out: &DeobOutput| out.rgf_eval_wrappers_inlined,
    );
}

#[test]
fn rgf_eval_bodies_actually_inlined() {
    if !node_available() {
        return;
    }
    let obf_path: PathBuf = recovery_dir().join("obf_tokenizer.rgf.js");
    let obf_src: String = fs::read_to_string(&obf_path).expect("read rgf sample");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);
    assert!(
        out.rgf_eval_wrappers_inlined > 0,
        "the rgf eval-payload wrappers must be inlined; got {}",
        out.rgf_eval_wrappers_inlined
    );
}

#[test]
fn real_jsconfuser_cff_is_devirtualized_to_straight_line() {
    if !node_available() {
        return;
    }
    let expectations: BTreeMap<String, String> =
        load_expectations().expect("expected.json must load");
    let want: &String = expectations
        .get("obf_statesum.real.js")
        .expect("real cff expectation");
    let obf_path: PathBuf = recovery_dir().join("obf_statesum.real.js");
    let obf_src: String = fs::read_to_string(&obf_path).expect("read real cff sample");

    let obf_runs: String =
        run_node(&obf_src).expect("real js-confuser cff sample must execute under node");
    assert_eq!(&obf_runs, want, "corpus drift on real cff sample");

    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);

    assert!(
        out.cff_generators_devirtualized > 0,
        "the real generator/with-wrapped cff must be devirtualized, not passed through; got 0"
    );
    for marker in ["function*", "with(", "[\"next\"]()[\"value\"]"] {
        assert!(
            !out.source.contains(marker),
            "the generator/with/dispatcher envelope marker {marker:?} must be gone; recovered:\n{}",
            out.source
        );
    }
    let recovered_runs: String = run_node(&out.source).unwrap_or_else(|| {
        panic!(
            "the devirtualized cff must still execute under node; recovered:\n{}",
            out.source
        )
    });
    assert_eq!(
        &recovered_runs, want,
        "behavioral divergence after devirtualizing the real cff envelope\nrecovered:\n{}",
        out.source
    );
}

const RUNTIME_BATTERY: &[&str] = &["10", "100", "0", "-7", "42", "1", "999"];
const BRANCH_BATTERY: &[&str] = &["150", "101", "100", "50", "11", "10", "5", "0"];
const STRINGS_BATTERY: &[&str] = &["world", "planet", "sun", "a"];
const LOOP_BATTERY: &[&str] = &["10", "1", "0", "7", "100", "3", "25", "50"];

fn grade_runtime_cff(obf_file: &str, src_file: &str, battery: &[&str]) {
    if !node_available() {
        return;
    }
    let obf_src: String = fs::read_to_string(recovery_dir().join(obf_file))
        .unwrap_or_else(|_| panic!("read {obf_file}"));
    let original_src: String = fs::read_to_string(recovery_dir().join(src_file))
        .unwrap_or_else(|_| panic!("read {src_file}"));

    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);
    assert!(
        out.cff_generators_devirtualized > 0,
        "{obf_file}: runtime cff must be devirtualized, got 0"
    );
    for marker in ["function*", "with(", "[\"next\"]()[\"value\"]"] {
        assert!(
            !out.source.contains(marker),
            "{obf_file}: envelope marker {marker:?} must be gone; recovered:\n{}",
            out.source
        );
    }

    for arg in battery {
        let original: String = run_node_with_args(&original_src, &[arg])
            .unwrap_or_else(|| panic!("{src_file} must run under node for arg {arg}"));
        let obfuscated: String = run_node_with_args(&obf_src, &[arg])
            .unwrap_or_else(|| panic!("{obf_file} must run under node for arg {arg}"));
        let recovered: String = run_node_with_args(&out.source, &[arg]).unwrap_or_else(|| {
            panic!(
                "recovered {obf_file} must run under node for arg {arg}:\n{}",
                out.source
            )
        });
        assert_eq!(
            original, obfuscated,
            "corpus drift: {obf_file} diverges from {src_file} at arg {arg}"
        );
        assert_eq!(
            original, recovered,
            "{obf_file}: devirtualized output diverges from the original at arg {arg}\nrecovered:\n{}",
            out.source
        );
    }
}

#[test]
fn real_runtime_branchless_cff_devirtualized_keeps_runtime_input() {
    grade_runtime_cff(
        "obf_statesum_runtime.real.js",
        "src_statesum_runtime.js",
        RUNTIME_BATTERY,
    );
}

#[test]
fn real_runtime_branch_cff_devirtualized_keeps_both_edges() {
    grade_runtime_cff(
        "obf_statesum_branch.real.js",
        "src_statesum_branch.js",
        BRANCH_BATTERY,
    );
}

#[test]
fn real_runtime_string_loop_cff_devirtualized() {
    grade_runtime_cff(
        "obf_statesum_strings.real.js",
        "src_statesum_strings.js",
        STRINGS_BATTERY,
    );
}

#[test]
fn real_runtime_tripcount_loop_relooped_keeps_runtime_bound() {
    grade_runtime_cff(
        "obf_statesum_loop.real.js",
        "src_statesum_loop.js",
        LOOP_BATTERY,
    );
}

const CLASSIFY_BATTERY: &[&str] = &["150", "101", "100", "50", "11", "10", "5", "0"];

fn grade_static_input(obf_file: &str, src_file: &str, battery: &[&[&str]]) -> DeobOutput {
    let obf_src: String = fs::read_to_string(recovery_dir().join(obf_file))
        .unwrap_or_else(|_| panic!("read {obf_file}"));
    let original_src: String = fs::read_to_string(recovery_dir().join(src_file))
        .unwrap_or_else(|_| panic!("read {src_file}"));

    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);

    for args in battery {
        let original: String = run_node_with_args(&original_src, args)
            .unwrap_or_else(|| panic!("{src_file} must run under node for {args:?}"));
        let obfuscated: String = run_node_with_args(&obf_src, args)
            .unwrap_or_else(|| panic!("{obf_file} must run under node for {args:?}"));
        let recovered: String = run_node_with_args(&out.source, args).unwrap_or_else(|| {
            panic!(
                "recovered {obf_file} must run under node for {args:?}:\n{}",
                out.source
            )
        });
        assert_eq!(
            original, obfuscated,
            "corpus drift: {obf_file} diverges from {src_file} at {args:?}"
        );
        assert_eq!(
            original, recovered,
            "{obf_file}: recovered output diverges from the original at {args:?}\nrecovered:\n{}",
            out.source
        );
    }
    out
}

#[test]
fn real_dead_code_branches_removed_behavior_matches_node() {
    if !node_available() {
        return;
    }
    let battery: Vec<Vec<&str>> = CLASSIFY_BATTERY.iter().map(|a| vec![*a]).collect();
    let battery_refs: Vec<&[&str]> = battery.iter().map(Vec::as_slice).collect();
    let out: DeobOutput =
        grade_static_input("obf_deadcode.real.js", "src_deadcode.js", &battery_refs);
    assert!(
        out.dead_code_branches_removed > 0,
        "the deadCode `\"x\" in dummy` guards must be removed; got 0"
    );
    assert!(
        out.dead_code_functions_removed > 0,
        "the injected dead function declarations must be removed; got 0"
    );
    assert!(
        !out.source.contains("dummyFunction") && !out.source.contains("_dead_"),
        "no deadCode scaffolding may remain:\n{}",
        out.source
    );
}

#[test]
fn real_dead_code_with_cff_behavior_matches_node() {
    if !node_available() {
        return;
    }
    let battery: Vec<Vec<&str>> = CLASSIFY_BATTERY.iter().map(|a| vec![*a]).collect();
    let battery_refs: Vec<&[&str]> = battery.iter().map(Vec::as_slice).collect();
    let out: DeobOutput =
        grade_static_input("obf_deadcode_cff.real.js", "src_deadcode.js", &battery_refs);
    assert!(
        out.cff_generators_devirtualized > 0,
        "the combined deadCode+cff sample must devirtualize the dispatcher; got 0"
    );
    for marker in ["function*", "with(", "[\"next\"]()[\"value\"]"] {
        assert!(
            !out.source.contains(marker),
            "the cff envelope marker {marker:?} must be gone after deadCode+cff recovery:\n{}",
            out.source
        );
    }
}

#[test]
fn real_integrity_self_check_unwrapped_behavior_matches_node() {
    if !node_available() {
        return;
    }
    let battery: &[&[&str]] = &[
        &["2", "3"],
        &["10", "20"],
        &["0", "0"],
        &["-5", "7"],
        &["7", "6"],
    ];
    let out: DeobOutput = grade_static_input("obf_integrity.real.js", "src_integrity.js", battery);
    assert!(
        out.integrity_self_checks_unwrapped > 0,
        "the integrity self-check wrappers must be unwrapped; got 0"
    );
    assert!(
        !out.source.contains("while (true)") && !out.source.contains("while(true)"),
        "the tamper trap must be gone:\n{}",
        out.source
    );
}

#[test]
fn runtime_tripcount_loop_is_relooped_not_unrolled() {
    if !node_available() {
        return;
    }
    let obf_src: String = fs::read_to_string(recovery_dir().join("obf_statesum_loop.real.js"))
        .expect("read runtime loop sample");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&obf_src, &opts);
    assert!(
        out.cff_generators_devirtualized > 0,
        "the runtime-trip-count loop cff must be devirtualized; got 0"
    );
    assert!(
        out.source.contains("while ("),
        "the runtime-bounded loop must be relooped into a structured while, not unrolled or passed through:\n{}",
        out.source
    );
    assert!(
        !out.source.contains("function*")
            && !out.source.contains("with(")
            && !out.source.contains("[\"next\"]()[\"value\"]"),
        "the generator/with/dispatcher envelope must be gone:\n{}",
        out.source
    );
    assert_eq!(
        out.source.matches("while (").count(),
        1,
        "exactly one structured loop must remain after dead-loop pruning:\n{}",
        out.source
    );
}

#[test]
fn real_jsconfuser_cff_is_detected() {
    let obf_path: PathBuf = recovery_dir().join("obf_statesum.real.js");
    let obf_src: String = fs::read_to_string(&obf_path).expect("read real cff sample");
    let detection: disrobe_pass_js_deob::Detection =
        disrobe_pass_js_deob::detect(obf_src.as_bytes());
    assert_eq!(
        detection.family,
        disrobe_pass_js_deob::JsObfuscator::JsConfuser,
        "the real generator-wrapped cff output must still be recognized as JSConfuser"
    );
}
