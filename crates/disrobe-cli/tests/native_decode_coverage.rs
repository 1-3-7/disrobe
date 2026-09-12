#![cfg(feature = "nir-lift")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::PathBuf;

use serde_json::Value;

const SCALAR: &str = "tests/fixtures/native_aarch64_scalar_post_index.elf";
const SYSTEM_OPS: &str = "tests/fixtures/native_aarch64_system_ops.elf";
const STATUSES: [&str; 7] = [
    "ambiguous",
    "callother",
    "no_match",
    "spec_error",
    "supported",
    "truncated",
    "unsupported",
];

fn decompile(fixture: &str) -> (common::Run, Value) {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(fixture);
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create output directory");
    let output: PathBuf = scratch.path().join("out");
    let run: common::Run = common::run_disrobe(&[
        "native",
        "decompile",
        &path.display().to_string(),
        "--backend",
        "native",
        "--format",
        "c",
        "--out",
        &output.display().to_string(),
    ]);
    assert_eq!(
        run.code, 0,
        "native decompile must succeed on {fixture}; stderr={}",
        run.stderr
    );
    let manifest: PathBuf = output.join("manifest.json");
    let text: String = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest.display()));
    let parsed: Value = serde_json::from_str(&text).expect("manifest must be JSON");
    (run, parsed)
}

fn coverage(manifest: &Value) -> &Value {
    manifest
        .get("decode_coverage")
        .unwrap_or_else(|| panic!("the manifest must carry a decode_coverage block: {manifest}"))
}

fn number(block: &Value, field: &str) -> u64 {
    block[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} must be a number: {block}"))
}

fn text(block: &Value, field: &str) -> String {
    block[field]
        .as_str()
        .unwrap_or_else(|| {
            panic!("{field} must be a string so no float printer can reformat it: {block}")
        })
        .to_owned()
}

fn status_count(block: &Value, status: &str) -> u64 {
    block["by_status"]
        .as_array()
        .expect("by_status must be an array")
        .iter()
        .find(|share: &&Value| share["status"] == status)
        .and_then(|share: &Value| share["instructions"].as_u64())
        .unwrap_or_else(|| panic!("the {status} share must be present: {block}"))
}

fn two_fraction_digits(label: &str, percent: &str) {
    let (units, fraction): (&str, &str) = percent
        .split_once('.')
        .unwrap_or_else(|| panic!("{label} must carry a decimal point: {percent}"));
    assert!(
        !units.is_empty() && units.chars().all(|digit: char| digit.is_ascii_digit()),
        "{label} must be a plain decimal figure: {percent}"
    );
    assert_eq!(
        fraction.len(),
        2,
        "{label} must keep exactly two fractional digits, so a run that recovers 99.99 per cent \
         is never rounded into a claim of full coverage: {percent}"
    );
    assert!(
        fraction.chars().all(|digit: char| digit.is_ascii_digit()),
        "{label} must be a plain decimal figure: {percent}"
    );
}

const fn hundredths(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    (part * 10_000 + whole / 2) / whole
}

fn agrees_with_counts(label: &str, percent: &str, part: u64, whole: u64) {
    let (units, fraction): (&str, &str) = percent
        .split_once('.')
        .unwrap_or_else(|| panic!("{label} must carry a decimal point: {percent}"));
    let reported: u64 = units.parse::<u64>().expect("units must parse") * 100
        + fraction.parse::<u64>().expect("fraction must parse");
    let computed: u64 = hundredths(part, whole);
    assert!(
        reported.abs_diff(computed) <= 1,
        "{label} must equal {part} of {whole} recomputed from the counts printed beside it; \
         reported={percent} computed={}.{:02}",
        computed / 100,
        computed % 100
    );
}

#[test]
fn decode_coverage_names_every_status_the_decoder_can_report() {
    let (_run, manifest): (common::Run, Value) = decompile(SCALAR);
    let block: &Value = coverage(&manifest);
    assert_eq!(block["schema"], "disrobe.native.decode-coverage/v1");
    let by_status: &Vec<Value> = block["by_status"]
        .as_array()
        .expect("by_status must be an array");
    let reported: Vec<&str> = by_status
        .iter()
        .filter_map(|share: &Value| share["status"].as_str())
        .collect();
    assert_eq!(
        reported, STATUSES,
        "every DecodeStatus variant must be named, in a stable order, so a status that never \
         occurs is still visibly zero rather than absent"
    );
    let counted: u64 = by_status
        .iter()
        .filter_map(|share: &Value| share["instructions"].as_u64())
        .sum();
    assert!(
        counted > 0,
        "the fixture decodes instructions, so the per-status counts cannot all be zero"
    );
}

#[test]
fn decode_coverage_agrees_digit_for_digit_between_human_and_json_output() {
    for fixture in [SCALAR, SYSTEM_OPS] {
        let (run, manifest): (common::Run, Value) = decompile(fixture);
        let block: &Value = coverage(&manifest);
        let matched: String = text(block, "matched_percent");
        let semantic: String = text(block, "semantic_percent");
        let decoded: u64 = number(block, "decoded_instructions");
        let line: &str = run
            .stdout
            .lines()
            .find(|line: &&str| line.trim_start().starts_with("decode coverage:"))
            .unwrap_or_else(|| {
                panic!(
                    "the human output must print a decode coverage line for {fixture}: {}",
                    run.stdout
                )
            });
        assert!(
            line.contains(&format!("{decoded} decoded")),
            "the human line must print the same decoded count as the manifest; line={line}"
        );
        assert!(
            line.contains(&format!("({matched}%)")),
            "the human line must print the manifest matched percent digit for digit; line={line}"
        );
        assert!(
            line.contains(&format!("({semantic}%)")),
            "the human line must print the manifest semantic percent digit for digit; line={line}"
        );
        two_fraction_digits("matched_percent", &matched);
        two_fraction_digits("semantic_percent", &semantic);
        agrees_with_counts(
            "matched_percent",
            &matched,
            number(block, "matched_instructions"),
            decoded,
        );
        agrees_with_counts(
            "semantic_percent",
            &semantic,
            status_count(block, "supported"),
            decoded,
        );
        for share in block["by_status"]
            .as_array()
            .expect("by_status must be an array")
        {
            let status: &str = share["status"].as_str().expect("status must be a string");
            let percent: &str = share["percent_of_decoded"]
                .as_str()
                .expect("percent_of_decoded must be a string");
            two_fraction_digits(status, percent);
            agrees_with_counts(
                status,
                percent,
                share["instructions"].as_u64().expect("count must be u64"),
                decoded,
            );
        }
    }
}

#[test]
fn matched_and_semantic_are_reported_as_different_measures() {
    let (run, manifest): (common::Run, Value) = decompile(SYSTEM_OPS);
    let block: &Value = coverage(&manifest);
    let decoded: u64 = number(block, "decoded_instructions");
    let matched: u64 = number(block, "matched_instructions");
    let supported: u64 = status_count(block, "supported");
    let callother: u64 = status_count(block, "callother");
    let unsupported: u64 = status_count(block, "unsupported");
    assert_eq!(
        decoded, 9,
        "native_aarch64_system_ops.s assembles nine instructions"
    );
    assert_eq!(
        supported, 3,
        "only add, add and ret carry full semantics in native_aarch64_system_ops.s; the six \
         system instructions do not"
    );
    assert_eq!(
        callother, 4,
        "mrs, dmb, svc and isb decode to callother in native_aarch64_system_ops.s"
    );
    assert_eq!(
        unsupported, 2,
        "msr and dc are reported unsupported in native_aarch64_system_ops.s"
    );
    assert_eq!(
        matched,
        supported + callother + unsupported,
        "matched must be exactly supported plus callother plus unsupported, which is what the \
         note beside it claims"
    );
    assert!(
        matched > supported,
        "on an input carrying system instructions the two figures must diverge, otherwise a \
         reader cannot tell a matched instruction from a semantically lifted one; \
         matched={matched} supported={supported}"
    );
    assert_eq!(
        text(block, "matched_percent"),
        "100.00",
        "every instruction in native_aarch64_system_ops.s is matched by the decoder"
    );
    assert_eq!(
        text(block, "semantic_percent"),
        "33.33",
        "three of nine instructions are semantically lifted, so the run must not claim full \
         recovery merely because every instruction decoded"
    );
    let emitting: u64 = number(block, "instructions_emitting_callother");
    assert_eq!(
        emitting, 6,
        "six instructions lift to a body containing a callother operation"
    );
    assert_ne!(
        emitting, callother,
        "the callother status count and the count of instructions emitting a callother operation \
         are different measures and must not share one name in one report"
    );
    assert!(
        run.stdout.contains("emitting callother"),
        "the human line must name the emitting-callother figure as such rather than calling it \
         the callother count; stdout={}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("matched counts supported, callother and unsupported"),
        "the human output must say what each figure counts, so matched is not read as semantic \
         coverage; stdout={}",
        run.stdout
    );
}

#[test]
fn unlifted_mnemonics_are_a_counted_map_rather_than_a_repeated_list() {
    let (_run, manifest): (common::Run, Value) = decompile(SYSTEM_OPS);
    let block: &Value = coverage(&manifest);
    let unlifted: &serde_json::Map<String, Value> = block["unlifted_mnemonics"]
        .as_object()
        .expect("unlifted_mnemonics must be an object keyed by mnemonic");
    let named: Vec<&str> = unlifted.keys().map(String::as_str).collect();
    assert_eq!(
        named,
        ["dc", "dmb", "isb", "mrs", "msr", "svc"],
        "every system instruction in native_aarch64_system_ops.s must be named once, in a stable \
         order, so a reader can see exactly which mnemonics were not lifted"
    );
    for (mnemonic, count) in unlifted {
        assert_eq!(
            count.as_u64(),
            Some(1),
            "{mnemonic} occurs once in native_aarch64_system_ops.s and must carry an occurrence \
             count rather than appearing repeatedly"
        );
    }
    assert!(
        status_count(block, "supported") < number(block, "decoded_instructions"),
        "an input with an unlifted mnemonic cannot report every decoded instruction as \
         semantically lifted"
    );
}

#[test]
fn the_scalar_post_index_fixture_reports_every_instruction_matched_and_lifted() {
    let (run, manifest): (common::Run, Value) = decompile(SCALAR);
    let block: &Value = coverage(&manifest);
    assert_eq!(
        number(block, "decoded_instructions"),
        8,
        "native_aarch64_scalar_post_index.s assembles eight instructions across two functions"
    );
    assert_eq!(
        status_count(block, "supported"),
        8,
        "the two scalar post-index floating-point transfers this fixture is named for are \
         semantically lifted alongside the six general-register loads, stores and returns"
    );
    assert_eq!(
        status_count(block, "no_match"),
        0,
        "the decoder must match a constructor for every instruction in the fixture named after \
         the shape it exercises"
    );
    assert_eq!(
        status_count(block, "unsupported"),
        0,
        "a matched constructor without semantics would still leave the recovered body incomplete"
    );
    assert_eq!(
        status_count(block, "callother"),
        0,
        "no instruction in native_aarch64_scalar_post_index.s decodes to callother"
    );
    assert_eq!(
        number(block, "instructions_emitting_callother"),
        0,
        "a fully lifted body carries no callother operation"
    );
    let unlifted: Vec<(&str, u64)> = block["unlifted_mnemonics"]
        .as_object()
        .expect("unlifted_mnemonics must be an object")
        .iter()
        .map(|(mnemonic, count): (&String, &Value)| {
            (
                mnemonic.as_str(),
                count.as_u64().expect("a count must be a number"),
            )
        })
        .collect();
    assert_eq!(
        unlifted,
        Vec::<(&str, u64)>::new(),
        "no mnemonic may remain unlifted, so the raw .inst directive can never come back"
    );
    assert!(
        run.stdout.contains("emitting callother"),
        "the human line must name the emitting-callother figure as such; stdout={}",
        run.stdout
    );
}
