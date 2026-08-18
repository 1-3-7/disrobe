#![cfg(feature = "nir-lift")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

const FIXTURE_ELF: &str = "tests/fixtures/native_aarch64_simd_memory.elf";
const FIXTURE_SOURCE: &str = "tests/fixtures/native_aarch64_simd_memory.s";
const DECODED_INSTRUCTIONS: u64 = 32;
const VECTOR_WIDTHS: [char; 5] = ['b', 'd', 'h', 'q', 's'];

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn source_instructions() -> Vec<String> {
    let path: PathBuf = fixture(FIXTURE_SOURCE);
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    text.lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty() && !line.starts_with('.') && !line.ends_with(':'))
        .map(str::to_owned)
        .collect()
}

fn vector_width(operands: &str) -> Option<char> {
    let first: &str = operands.split(',').next()?.trim();
    let mut characters: std::str::Chars<'_> = first.chars();
    let width: char = characters.next()?;
    let index: String = characters.collect();
    let numbered: bool =
        !index.is_empty() && index.chars().all(|digit: char| digit.is_ascii_digit());
    (VECTOR_WIDTHS.contains(&width) && numbered).then_some(width)
}

fn class_of(instruction: &str) -> &'static str {
    let (mnemonic, operands): (&str, &str) =
        instruction.split_once(' ').unwrap_or((instruction, ""));
    let addressing: &str = operands
        .split_once('[')
        .map_or("", |(_, rest): (&str, &str)| rest);
    let vector: bool = vector_width(operands).is_some();
    let writeback: bool = addressing.contains('!') || addressing.contains("], #");
    let register_offset: bool = addressing.contains(", x") || addressing.contains(", w");
    match (mnemonic, vector) {
        ("ldur" | "stur", true) => "simd_unscaled",
        ("ldp" | "stp", true) if writeback => "pair_writeback",
        ("ldp" | "stp", true) => "pair_offset",
        ("ldr" | "str", true) if register_offset => "simd_register_offset",
        ("ldr" | "str", true) => "simd_scaled_offset",
        ("ldur" | "stur" | "ldr" | "str" | "ldp" | "stp", false) => "general_memory",
        _ => "not_a_memory_access",
    }
}

fn census() -> BTreeMap<&'static str, usize> {
    let mut counted: BTreeMap<&'static str, usize> = BTreeMap::new();
    for instruction in source_instructions() {
        *counted.entry(class_of(&instruction)).or_default() += 1;
    }
    counted
}

fn decompile() -> (common::Run, Value) {
    let path: PathBuf = fixture(FIXTURE_ELF);
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
        "native decompile must succeed on the simd memory fixture; stderr={}",
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

fn status_count(block: &Value, status: &str) -> u64 {
    block["by_status"]
        .as_array()
        .expect("by_status must be an array")
        .iter()
        .find(|share: &&Value| share["status"] == status)
        .and_then(|share: &Value| share["instructions"].as_u64())
        .unwrap_or_else(|| panic!("the {status} share must be present: {block}"))
}

#[test]
fn the_fixture_carries_every_memory_addressing_class_it_is_named_for() {
    let counted: BTreeMap<&'static str, usize> = census();
    let expected: BTreeMap<&'static str, usize> = BTreeMap::from([
        ("simd_unscaled", 10),
        ("simd_register_offset", 8),
        ("pair_offset", 4),
        ("pair_writeback", 4),
        ("general_memory", 3),
        ("not_a_memory_access", 3),
    ]);
    assert_eq!(
        counted, expected,
        "the fixture must keep one instruction of every addressing class the simd memory lift \
         claims, so a later edit cannot leave a full-coverage figure standing over a fixture that \
         no longer exercises unscaled, register-offset or writeback-pair addressing"
    );
    let widths: BTreeSet<char> = source_instructions()
        .iter()
        .filter(|instruction: &&String| class_of(instruction).starts_with("simd"))
        .filter_map(|instruction: &String| {
            vector_width(
                instruction
                    .split_once(' ')
                    .map_or("", |(_, rest): (&str, &str)| rest),
            )
        })
        .collect();
    assert_eq!(
        widths,
        BTreeSet::from(VECTOR_WIDTHS),
        "every vector width the memory encodings select between must appear, so a lift that \
         handles only the sixty-four and one-hundred-twenty-eight bit forms cannot report full \
         coverage"
    );
    assert_eq!(
        source_instructions().len() as u64,
        DECODED_INSTRUCTIONS,
        "the committed assembly and the count the coverage assertions expect must agree, so a \
         rebuilt object can never silently carry a different program than the source beside it"
    );
}

#[test]
fn every_simd_memory_form_reaches_the_decompiler_with_semantics() {
    let (run, manifest): (common::Run, Value) = decompile();
    let block: &Value = coverage(&manifest);
    let decoded: u64 = block["decoded_instructions"]
        .as_u64()
        .expect("decoded_instructions must be a number");
    assert_eq!(
        decoded, DECODED_INSTRUCTIONS,
        "llvm-objdump disassembles thirty-two instructions in this object, so the decoder must \
         reach the same count before any coverage figure it prints can be read"
    );
    assert_eq!(
        status_count(block, "supported"),
        DECODED_INSTRUCTIONS,
        "every unscaled, register-offset and pair form in the fixture must carry semantics on the \
         command-line path, not only in the specification test that graded the encodings"
    );
    for absent in [
        "no_match",
        "unsupported",
        "callother",
        "ambiguous",
        "spec_error",
        "truncated",
    ] {
        assert_eq!(
            status_count(block, absent),
            0,
            "no instruction in the fixture may be reported {absent}: {block}"
        );
    }
    assert_eq!(
        block["instructions_emitting_callother"].as_u64(),
        Some(0),
        "a fully lifted body carries no callother operation"
    );
    assert_eq!(
        block["semantic_percent"].as_str(),
        Some("100.00"),
        "the semantic figure must read as full coverage digit for digit: {block}"
    );
    let unlifted: &serde_json::Map<String, Value> = block["unlifted_mnemonics"]
        .as_object()
        .expect("unlifted_mnemonics must be an object keyed by mnemonic");
    assert!(
        unlifted.is_empty(),
        "no mnemonic may remain unlifted; a regression must name itself here: {unlifted:?}"
    );
    assert!(
        run.stdout.contains("32 semantically lifted (100.00%)"),
        "the human output must state the same figure the manifest carries; stdout={}",
        run.stdout
    );
}
