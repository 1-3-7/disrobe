#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{DeobOptions, DeobOutput, deobfuscate_all};
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};

mod common;

const OBFUSCATED_SHA256: [(&str, &str); 12] = [
    (
        "obf_checksum.stringconceal.js",
        "aefef83a730c3e2efff221eb456d355796f33574ef581bfc94bfe378e2d5e23b",
    ),
    (
        "obf_deadcode.real.js",
        "4d38daaacd0ef6474a7633983aa7bd833f592c6ea853d602159222f6510f5c33",
    ),
    (
        "obf_deadcode_cff.real.js",
        "0df41a192ebb82a06ad72d1564dd08ddcc9269a4ac4096b722b62edd7ba25af3",
    ),
    (
        "obf_integrity.real.js",
        "40a2bf771693b854dd2a49cb2b957ef58d858ab16bbc9316b34dca5733500657",
    ),
    (
        "obf_statesum.real.js",
        "2f98fa53da1e905e0df0dca424e4069f503f20dc9376b08a9289f58371c5b0ae",
    ),
    (
        "obf_statesum.spec.js",
        "a585bac3f3f7422b181f5dfe430be901f9ace34b918f6ba4cc91da4cc2aa5434",
    ),
    (
        "obf_statesum_branch.real.js",
        "5cf89a6d1f0a005bc52e8fff2b6281b3785badada6f46dc272c126f076583e52",
    ),
    (
        "obf_statesum_loop.real.js",
        "8bcb45258e538becec707eb9a2baaddc84f22e6af85e6c4d629982e69d8bb0de",
    ),
    (
        "obf_statesum_runtime.real.js",
        "3ce67fb4fd819b3d6eba10adf2585f8ac7069313382f4dab3a46dd2abe7aafdd",
    ),
    (
        "obf_statesum_strings.real.js",
        "0f6ddf23bd1b99c174e7986ea8b3afdf625602b4fd8b11e5521c3e0d73a782dd",
    ),
    (
        "obf_stringcompression.real.js",
        "58faa0a51ae71f6b08a8f4647bba61abde4076e3b6c7442ccfc8fcd3ba629085",
    ),
    (
        "obf_tokenizer.rgf.js",
        "6725454bf66219571d38ddbf55840b81c2e001e248f17ba11254da946c552fd1",
    ),
];

const CFF_ENVELOPE_MARKERS: [&str; 3] = ["function*", "with(", "[\"next\"]()[\"value\"]"];

fn recovery_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join("jsconfuser")
        .join("recovery")
}

fn run_authored_node(source_file: &str, args: &[&str]) -> Option<String> {
    let output: std::process::Output = std::process::Command::new("node")
        .env_remove("FORCE_COLOR")
        .env("NO_COLOR", "1")
        .arg("--")
        .arg(recovery_dir().join(source_file))
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn read_obfuscated(file: &str) -> String {
    let Some((_, pinned)): Option<&(&str, &str)> = OBFUSCATED_SHA256
        .iter()
        .find(|(name, _): &&(&str, &str)| *name == file)
    else {
        panic!("{file} carries no pinned SHA-256");
    };
    let source: String =
        fs::read_to_string(recovery_dir().join(file)).unwrap_or_else(|_| panic!("read {file}"));
    assert_eq!(
        format!("{:x}", Sha256::digest(source.as_bytes())),
        *pinned,
        "corpus drift: {file} is no longer the js-confuser 2.0.1 output whose behavior \
         expected.json and the source batteries record"
    );
    source
}

#[test]
fn recovered_stdout_oracle_detects_an_extra_line() {
    let source: String = read_obfuscated("obf_tokenizer.rgf.js");
    let recovered: DeobOutput = deobfuscate_all(&source, &DeobOptions::all())
        .expect("jsconfuser deobfuscation must not refuse");
    let original: String = common::eval_stdout_with_argv(&recovered.source, &[])
        .expect("recovered tokenizer must evaluate inside the bounded engine");
    let mutated: String = format!("{}\nconsole.log('extra');", recovered.source);
    let changed: String = common::eval_stdout_with_argv(&mutated, &[])
        .expect("mutated tokenizer must evaluate inside the bounded engine");
    assert_ne!(
        original, changed,
        "extra output must fail the behavior grade"
    );
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

fn assert_markers_gone(label: &str, out: &DeobOutput, markers: &[&str]) {
    let concealed_call: Regex =
        Regex::new(r"\b__p_\w+?_STR(?:_\d+)?\s*\(\s*\d").expect("concealed accessor call pattern");
    assert!(
        !concealed_call.is_match(&out.source),
        "{label}: concealed accessor calls remain and must be refused before execution"
    );
    for marker in markers {
        assert!(
            !out.source.contains(marker),
            "{label}: the obfuscation marker {marker:?} must be gone before the recovered source \
             runs; behavioral identity alone is not enough since the obfuscated form already \
             runs:\n{}",
            out.source
        );
    }
}

fn grade(
    sample_file: &str,
    source_file: &str,
    removed_markers: &[&str],
    recovery_signal: fn(&DeobOutput) -> usize,
) {
    let expectations: BTreeMap<String, String> =
        load_expectations().expect("expected.json must load");
    let want: &String = expectations
        .get(sample_file)
        .unwrap_or_else(|| panic!("no expectation recorded for {sample_file}"));
    let obf_src: String = read_obfuscated(sample_file);

    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&obf_src, &opts).expect("jsconfuser deobfuscation must not refuse");

    assert!(
        recovery_signal(&out) > 0,
        "deob of {sample_file} must report real recovery work, not a no-op pass-through",
    );
    assert_markers_gone(sample_file, &out, removed_markers);

    let authored_runs: String = run_authored_node(source_file, &[])
        .unwrap_or_else(|| panic!("the authored {source_file} must run under node"));
    assert_eq!(
        &authored_runs, want,
        "expected.json no longer records what {source_file} prints, so it cannot grade \
         {sample_file}"
    );
    let recovered_runs: String =
        common::eval_stdout_with_argv(&out.source, &[]).unwrap_or_else(|| {
            panic!(
                "recovered {sample_file} must evaluate inside bounded Boa; recovered:\n{}",
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
        "src_statesum.js",
        &["s0 + s1 + s2", "t0 + t1", "switch ("],
        |out: &DeobOutput| out.state_sum_machines_linearized,
    );
}

#[test]
fn state_sum_cff_dispatcher_is_actually_collapsed() {
    let obf_src: String = read_obfuscated("obf_statesum.spec.js");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&obf_src, &opts).expect("jsconfuser deobfuscation must not refuse");
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
    grade(
        "obf_checksum.stringconceal.js",
        "src_checksum.js",
        &[],
        |out: &DeobOutput| out.string_conceal_call_sites_decoded,
    );
}

#[test]
#[should_panic(expected = "concealed accessor calls remain")]
fn nested_concealed_accessor_is_refused_before_execution() {
    let out: DeobOutput = deobfuscate_all("__p_inner_STR_1(123)", &DeobOptions::all())
        .expect("jsconfuser deobfuscation must not refuse");
    assert_markers_gone("nested accessor mutant", &out, &[]);
}

#[test]
fn string_conceal_literals_actually_decoded() {
    let obf_src: String = read_obfuscated("obf_checksum.stringconceal.js");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&obf_src, &opts).expect("jsconfuser deobfuscation must not refuse");
    assert_markers_gone("obf_checksum.stringconceal.js", &out, &[]);
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
        "src_stringcompression.js",
        &["[\"decompressFromUTF16\"](compressedString)"],
        |out: &DeobOutput| out.string_compression_blocks_reversed,
    );
}

#[test]
fn string_compression_literals_actually_decoded() {
    let obf_src: String = read_obfuscated("obf_stringcompression.real.js");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&obf_src, &opts).expect("jsconfuser deobfuscation must not refuse");
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
        "src_tokenizer.js",
        &["_rgf_eval(", "rgf_eval_integrity"],
        |out: &DeobOutput| out.rgf_eval_wrappers_inlined,
    );
}

#[test]
fn rgf_eval_bodies_actually_inlined() {
    let obf_src: String = read_obfuscated("obf_tokenizer.rgf.js");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&obf_src, &opts).expect("jsconfuser deobfuscation must not refuse");
    assert!(
        out.rgf_eval_wrappers_inlined > 0,
        "the rgf eval-payload wrappers must be inlined; got {}",
        out.rgf_eval_wrappers_inlined
    );
}

#[test]
fn real_jsconfuser_cff_is_devirtualized_to_straight_line() {
    grade(
        "obf_statesum.real.js",
        "src_statesum.js",
        &CFF_ENVELOPE_MARKERS,
        |out: &DeobOutput| out.cff_generators_devirtualized,
    );
}

const RUNTIME_BATTERY: &[&str] = &["10", "100", "0", "-7", "42", "1", "999"];
const BRANCH_BATTERY: &[&str] = &["150", "101", "100", "50", "11", "10", "5", "0"];
const STRINGS_BATTERY: &[&str] = &["world", "planet", "sun", "a"];
const LOOP_BATTERY: &[&str] = &["10", "1", "0", "7", "100", "3", "25", "50"];

fn assert_recovered_matches_source(
    obf_file: &str,
    src_file: &str,
    out: &DeobOutput,
    battery: &[&[&str]],
) {
    for args in battery {
        let original: String = run_authored_node(src_file, args)
            .unwrap_or_else(|| panic!("{src_file} must run under node for {args:?}"));
        let recovered: String =
            common::eval_stdout_with_argv(&out.source, args).unwrap_or_else(|| {
                panic!(
                    "recovered {obf_file} must evaluate inside bounded Boa for {args:?}:\n{}",
                    out.source
                )
            });
        assert_eq!(
            original, recovered,
            "{obf_file}: recovered output diverges from {src_file} at {args:?}\nrecovered:\n{}",
            out.source
        );
    }
}

fn single_argument_battery(values: &'static [&'static str]) -> Vec<&'static [&'static str]> {
    values.iter().map(std::slice::from_ref).collect()
}

fn grade_runtime_cff(obf_file: &str, src_file: &str, battery: &'static [&'static str]) {
    let obf_src: String = read_obfuscated(obf_file);
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&obf_src, &opts).expect("jsconfuser deobfuscation must not refuse");
    assert!(
        out.cff_generators_devirtualized > 0,
        "{obf_file}: runtime cff must be devirtualized, got 0"
    );
    assert_markers_gone(obf_file, &out, &CFF_ENVELOPE_MARKERS);

    assert_recovered_matches_source(obf_file, src_file, &out, &single_argument_battery(battery));
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

fn recover_static_input(obf_file: &str) -> DeobOutput {
    let obf_src: String = read_obfuscated(obf_file);
    let opts: DeobOptions = DeobOptions::all();
    deobfuscate_all(&obf_src, &opts).expect("jsconfuser deobfuscation must not refuse")
}

#[test]
fn real_dead_code_branches_removed_behavior_matches_node() {
    let out: DeobOutput = recover_static_input("obf_deadcode.real.js");
    assert!(
        out.dead_code_branches_removed > 0,
        "the deadCode `\"x\" in dummy` guards must be removed; got 0"
    );
    assert!(
        out.dead_code_functions_removed > 0,
        "the injected dead function declarations must be removed; got 0"
    );
    assert_markers_gone("obf_deadcode.real.js", &out, &["dummyFunction", "_dead_"]);

    assert_recovered_matches_source(
        "obf_deadcode.real.js",
        "src_deadcode.js",
        &out,
        &single_argument_battery(CLASSIFY_BATTERY),
    );
}

#[test]
fn real_dead_code_with_cff_behavior_matches_node() {
    let out: DeobOutput = recover_static_input("obf_deadcode_cff.real.js");
    assert!(
        out.cff_generators_devirtualized > 0,
        "the combined deadCode+cff sample must devirtualize the dispatcher; got 0"
    );
    assert_markers_gone("obf_deadcode_cff.real.js", &out, &CFF_ENVELOPE_MARKERS);

    assert_recovered_matches_source(
        "obf_deadcode_cff.real.js",
        "src_deadcode.js",
        &out,
        &single_argument_battery(CLASSIFY_BATTERY),
    );
}

#[test]
fn real_integrity_self_check_unwrapped_behavior_matches_node() {
    let out: DeobOutput = recover_static_input("obf_integrity.real.js");
    assert!(
        out.integrity_self_checks_unwrapped > 0,
        "the integrity self-check wrappers must be unwrapped; got 0"
    );
    assert_markers_gone(
        "obf_integrity.real.js",
        &out,
        &["while (true)", "while(true)"],
    );

    let battery: &[&[&str]] = &[
        &["2", "3"],
        &["10", "20"],
        &["0", "0"],
        &["-5", "7"],
        &["7", "6"],
    ];
    assert_recovered_matches_source("obf_integrity.real.js", "src_integrity.js", &out, battery);
}

#[test]
fn runtime_tripcount_loop_is_relooped_not_unrolled() {
    let obf_src: String = read_obfuscated("obf_statesum_loop.real.js");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&obf_src, &opts).expect("jsconfuser deobfuscation must not refuse");
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
fn every_obfuscated_sample_is_pinned_here_and_in_the_manifest() {
    #[derive(Deserialize)]
    struct Manifest {
        sample: Vec<Sample>,
    }
    #[derive(Deserialize)]
    struct Sample {
        file: String,
        sha256: String,
    }
    let raw: String =
        fs::read_to_string(recovery_dir().join("MANIFEST.toml")).expect("read MANIFEST.toml");
    let manifest: Manifest = toml::from_str(&raw).expect("parse corpus manifest");
    let recorded: BTreeSet<(&str, &str)> = manifest
        .sample
        .iter()
        .map(|sample: &Sample| (sample.file.as_str(), sample.sha256.as_str()))
        .collect();
    let expected: BTreeSet<(&str, &str)> = OBFUSCATED_SHA256.into_iter().collect();
    assert_eq!(
        recorded.len(),
        manifest.sample.len(),
        "duplicate corpus record"
    );
    assert_eq!(
        recorded, expected,
        "manifest digests must match the pinned corpus"
    );
    let mut on_disk: Vec<String> = fs::read_dir(recovery_dir())
        .expect("list the recovery corpus")
        .map(|entry: std::io::Result<fs::DirEntry>| {
            entry
                .expect("read a recovery corpus entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name: &String| name.starts_with("obf_"))
        .collect();
    on_disk.sort();
    let pinned: Vec<&str> = OBFUSCATED_SHA256
        .iter()
        .map(|(file, _): &(&str, &str)| *file)
        .collect();
    assert_eq!(
        on_disk, pinned,
        "every committed js-confuser output must carry a pinned digest"
    );
}

#[test]
fn real_jsconfuser_cff_is_detected() {
    let obf_src: String = read_obfuscated("obf_statesum.real.js");
    let detection: disrobe_pass_js_deob::Detection =
        disrobe_pass_js_deob::detect(obf_src.as_bytes());
    assert_eq!(
        detection.family,
        disrobe_pass_js_deob::JsObfuscator::JsConfuser,
        "the real generator-wrapped cff output must still be recognized as JSConfuser"
    );
}
