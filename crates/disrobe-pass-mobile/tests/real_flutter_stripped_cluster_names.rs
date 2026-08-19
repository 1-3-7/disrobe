#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_pass_mobile::{
    AotLiftReport, DartCodeName, DartFunctionSymbol, DartGraphRecoveryOptions,
    DartGraphRecoveryReport, DartGraphRecoveryStatus, DartLiftedFunction, Error, LibAppLayout,
    lift_libapp_aot, parse_libapp_so, recover_dart_pinned_elf,
};

const SAMPLE: &str = "libapp_arm64.so";

const SOURCE: &str = "disrobe_aot_sample.dart";

const PINNED_VERSION_HASH: &str = "ace654289f5abc240509fc941453ebc5";

const RECORDED_INSTRUCTIONS_TABLE_ENTRIES: usize = 3_237;

const RECORDED_SYMTAB_CODE_SYMBOLS: usize = 3_003;

const RECORDED_CLUSTER_NAMED_OFFSETS: usize = 2_831;

const RECORDED_SHARED_OFFSETS: usize = 2_692;

const RECORDED_MEMBER_AGREEMENTS: usize = 2_691;

const RECORDED_STRIPPED_STRUCTURED_BODIES: usize = 2_122;

const EXTENSION_SEPARATOR_DIVERGENCE: &str = "IterableExtensions.elementAtOrNull";

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/mobile/flutter/disrobe_sample")
        .join(name);
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("sample {} must be committed: {error}", path.display()),
    }
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    let mut raw: [u8; 8] = [0; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

fn strip_elf_symtab(bytes: &[u8]) -> Vec<u8> {
    const SHT_SYMTAB: u32 = 2;
    const SHT_NULL: u32 = 0;
    let mut out: Vec<u8> = bytes.to_vec();
    let section_header_offset: usize =
        usize::try_from(read_u64(&out, 40)).expect("section header offset fits");
    let entry_size: usize = usize::from(read_u16(&out, 58));
    let entry_count: usize = usize::from(read_u16(&out, 60));
    let mut cleared: usize = 0;
    for index in 0..entry_count {
        let base: usize = section_header_offset + index * entry_size;
        if read_u32(&out, base + 4) == SHT_SYMTAB {
            out[base + 4..base + 8].copy_from_slice(&SHT_NULL.to_le_bytes());
            cleared += 1;
        }
    }
    assert_eq!(
        cleared, 1,
        "the committed sample must carry exactly one .symtab for the strip to be meaningful"
    );
    out
}

fn member_of(name: &str) -> &str {
    let tail: &str = name
        .rsplit_once('.')
        .map_or(name, |(_, member): (&str, &str)| member);
    tail.strip_prefix("dyn:")
        .or_else(|| tail.strip_prefix("init:"))
        .unwrap_or(tail)
}

fn symtab_offsets(bytes: &[u8]) -> BTreeMap<u64, String> {
    let layout: LibAppLayout = parse_libapp_so(bytes).expect("parse committed libapp");
    layout
        .function_symbols
        .iter()
        .map(|symbol: &DartFunctionSymbol| (symbol.offset as u64, symbol.name.clone()))
        .collect::<BTreeMap<u64, String>>()
}

fn cluster_names(bytes: &[u8]) -> BTreeMap<u64, Vec<String>> {
    let report: DartGraphRecoveryReport =
        recover_dart_pinned_elf(bytes, &DartGraphRecoveryOptions::default())
            .expect("pinned cluster recovery");
    assert_eq!(
        report.status,
        DartGraphRecoveryStatus::Recovered,
        "the pinned sample must recover, reason={:?}",
        report.name_mode_reason
    );
    let mut grouped: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for entry in &report.code_names.entries {
        grouped
            .entry(entry.instructions_offset)
            .or_default()
            .push(entry.qualified_name.clone());
    }
    grouped
}

#[test]
fn the_committed_sample_carries_a_symbol_table_that_the_strip_removes() {
    let bytes: Vec<u8> = fixture(SAMPLE);
    let stripped: Vec<u8> = strip_elf_symtab(&bytes);
    let full: LibAppLayout = parse_libapp_so(&bytes).expect("parse unstripped");
    let bare: LibAppLayout = parse_libapp_so(&stripped).expect("parse stripped");
    assert_eq!(
        full.function_symbols.len(),
        RECORDED_SYMTAB_CODE_SYMBOLS,
        "the unstripped sample must expose its linker code symbols, which are the independent \
         reference this file grades against"
    );
    assert!(
        bare.function_symbols.is_empty(),
        "after clearing .symtab the ELF offset-to-name path must yield nothing, got {} symbols; \
         without this the stripped grade would silently read the symbol table it claims to replace",
        bare.function_symbols.len()
    );
    assert!(
        bare.isolate_snapshot_data.is_some() && bare.isolate_snapshot_instructions.is_some(),
        "the snapshot sections must still resolve from .dynsym after stripping .symtab"
    );
}

#[test]
fn the_instructions_table_covers_every_offset_the_linker_names() {
    let bytes: Vec<u8> = fixture(SAMPLE);
    let report: DartGraphRecoveryReport =
        recover_dart_pinned_elf(&bytes, &DartGraphRecoveryOptions::default())
            .expect("pinned cluster recovery");
    assert!(
        report.code_names.reason.is_empty(),
        "the pinned sample must decode its instructions table, got {:?}",
        report.code_names.reason
    );
    assert_eq!(
        report.code_names.table_entry_count, RECORDED_INSTRUCTIONS_TABLE_ENTRIES,
        "the instructions-table entry count is the snapshot preamble's own declared figure"
    );
    let boundaries: BTreeSet<u64> = report
        .code_names
        .boundaries
        .iter()
        .map(|boundary: &disrobe_pass_mobile::DartCodeBoundary| boundary.instructions_offset)
        .collect::<BTreeSet<u64>>();
    let symbols: BTreeMap<u64, String> = symtab_offsets(&bytes);
    let missing: Vec<u64> = symbols
        .keys()
        .copied()
        .filter(|offset: &u64| !boundaries.contains(offset))
        .collect::<Vec<u64>>();
    assert!(
        missing.is_empty(),
        "every linker-named code offset must appear in the instructions table decoded from the \
         read-only image; {} of {} are absent, first={:?}. a constant skew between the table and \
         the image base would surface here before any name is attributed",
        missing.len(),
        symbols.len(),
        missing.first().map(|offset: &u64| format!("{offset:#x}"))
    );
    assert!(
        report
            .code_names
            .boundaries
            .iter()
            .all(|boundary: &disrobe_pass_mobile::DartCodeBoundary| boundary.payload_length > 0),
        "every decoded payload span must be non-empty, otherwise the synthesized boundary \
         disassembles zero instructions and every body silently disappears"
    );
}

#[test]
fn a_stripped_libapp_recovers_offset_to_name_from_the_isolate_snapshot_clusters() {
    let bytes: Vec<u8> = fixture(SAMPLE);
    let stripped: Vec<u8> = strip_elf_symtab(&bytes);
    let reference: BTreeMap<u64, String> = symtab_offsets(&bytes);
    let recovered: BTreeMap<u64, Vec<String>> = cluster_names(&stripped);

    assert!(
        recovered.len() >= RECORDED_CLUSTER_NAMED_OFFSETS,
        "cluster-driven offset-to-name must name at least {RECORDED_CLUSTER_NAMED_OFFSETS} \
         distinct code offsets on the stripped image, got {}",
        recovered.len()
    );

    let mut compared: usize = 0;
    let mut agreed: usize = 0;
    let mut divergent: Vec<String> = Vec::new();
    for (offset, names) in &recovered {
        let Some(expected): Option<&String> = reference.get(offset) else {
            continue;
        };
        compared += 1;
        let want: &str = member_of(expected);
        if names.iter().any(|name: &String| member_of(name) == want) {
            agreed += 1;
        } else {
            divergent.push(expected.clone());
        }
    }
    println!(
        "stripped flutter offset-to-name vs the linker symbol table: member agreement \
         {agreed}/{compared}, distinct named offsets {}, instructions-table entries {}",
        recovered.len(),
        RECORDED_INSTRUCTIONS_TABLE_ENTRIES
    );
    assert!(
        agreed >= RECORDED_MEMBER_AGREEMENTS,
        "at every offset both sides name, the member recovered from the clusters must equal the \
         member the linker recorded; got {agreed}/{compared}, divergent={divergent:?}"
    );
    assert!(
        compared >= RECORDED_SHARED_OFFSETS,
        "the stripped walk and the linker symbol table must name at least \
         {RECORDED_SHARED_OFFSETS} offsets in common, got {compared}"
    );
    assert_eq!(
        divergent.as_slice(),
        [EXTENSION_SEPARATOR_DIVERGENCE],
        "the only accepted divergence is the extension-member separator, which the snapshot \
         spells with a bar and the linker spells with a dot; any other divergence is a \
         mis-attributed body"
    );
}

#[test]
fn cluster_recovered_names_are_present_in_the_snapshot_and_never_invented() {
    let bytes: Vec<u8> = fixture(SAMPLE);
    let stripped: Vec<u8> = strip_elf_symtab(&bytes);
    let report: DartGraphRecoveryReport =
        recover_dart_pinned_elf(&stripped, &DartGraphRecoveryOptions::default())
            .expect("pinned cluster recovery");
    let haystack: Vec<u8> = stripped;
    let mut absent: Vec<String> = Vec::new();
    for entry in &report.code_names.entries {
        let member: &str = member_of(&entry.member_name);
        if member.is_empty() {
            continue;
        }
        if !contains(&haystack, member.as_bytes()) {
            absent.push(entry.member_name.clone());
        }
    }
    assert!(
        absent.is_empty(),
        "every member name attributed to a code offset must occur verbatim in the image bytes; \
         {} do not and are therefore invented, first={:?}",
        absent.len(),
        absent.first()
    );
}

#[test]
fn a_stripped_libapp_lifts_named_pseudo_dart_bodies() {
    let bytes: Vec<u8> = fixture(SAMPLE);
    let stripped: Vec<u8> = strip_elf_symtab(&bytes);
    let report: AotLiftReport = lift_libapp_aot(&stripped).expect("lift the stripped image");
    println!(
        "stripped flutter lift: functions={} named={} cluster_named={} structured={}",
        report.function_count,
        report.named_function_count,
        report.cluster_named_function_count,
        report.structured_function_count
    );
    assert_eq!(
        report.version_hash, PINNED_VERSION_HASH,
        "the stripped image must still resolve its snapshot version"
    );
    assert!(
        report.named_function_count >= RECORDED_CLUSTER_NAMED_OFFSETS,
        "a stripped image must recover at least {RECORDED_CLUSTER_NAMED_OFFSETS} function names \
         with no symbol table, got {}",
        report.named_function_count
    );
    assert_eq!(
        report.cluster_named_function_count, report.named_function_count,
        "with no symbol table every recovered name must come from the cluster walk"
    );
    assert!(
        report.function_count >= RECORDED_INSTRUCTIONS_TABLE_ENTRIES,
        "every instructions-table payload must become a function boundary, got {} of {}",
        report.function_count,
        RECORDED_INSTRUCTIONS_TABLE_ENTRIES
    );
    assert!(
        report.named_function_count < report.function_count,
        "payloads with no declared owning function must stay unnamed rather than take a \
         fabricated label"
    );
    assert!(
        report.structured_function_count >= RECORDED_STRIPPED_STRUCTURED_BODIES,
        "a stripped image must structure at least {RECORDED_STRIPPED_STRUCTURED_BODIES} bodies \
         into pseudo-Dart, got {}",
        report.structured_function_count
    );
    assert!(
        report
            .notes
            .iter()
            .any(|note: &String| note.contains("instructions table")),
        "the report must name where the boundaries and names came from, notes={:?}",
        report.notes
    );

    let source: String = String::from_utf8(fixture(SOURCE)).expect("the sample source is utf-8");
    let target: &DartLiftedFunction = report
        .functions
        .iter()
        .find(|function: &&DartLiftedFunction| function.name.as_deref() == Some("fibonacciStep"))
        .expect("fibonacciStep must be named from the clusters alone on a stripped image");
    assert!(
        source.contains("int fibonacciStep(int depth)"),
        "the committed Dart source must declare fibonacciStep, which is what makes this name \
         independent of the recovery under test"
    );
    let body: String = target.best_pseudo_dart();
    assert!(
        body.matches("fibonacciStep(").count() >= 3,
        "the stripped lift of fibonacciStep must render its own signature and both recursive \
         calls by name, got:\n{body}"
    );
    assert!(
        source.contains("return fibonacciStep(depth - 1) + fibonacciStep(depth - 2);"),
        "the recursion the lift recovers must be the recursion the source declares"
    );
}

#[test]
fn an_unpinned_snapshot_version_abstains_with_a_named_reason() {
    let bytes: Vec<u8> = fixture(SAMPLE);
    let mut altered: Vec<u8> = bytes;
    let hash: &[u8] = PINNED_VERSION_HASH.as_bytes();
    let mut rewritten: usize = 0;
    let mut at: usize = 0;
    while let Some(found) = find_from(&altered, hash, at) {
        altered[found..found + hash.len()].copy_from_slice(b"00000000000000000000000000000000");
        rewritten += 1;
        at = found + hash.len();
    }
    assert!(
        rewritten >= 2,
        "both snapshot headers must carry the version hash for this abstain case to be real, \
         rewrote {rewritten}"
    );
    let report: DartGraphRecoveryReport =
        recover_dart_pinned_elf(&altered, &DartGraphRecoveryOptions::default())
            .expect("an unknown version must abstain rather than error");
    assert_eq!(
        report.status,
        DartGraphRecoveryStatus::UnsupportedVersion,
        "an unrecognized snapshot version must abstain, not read another layout's offsets"
    );
    assert!(
        report.code_names.entries.is_empty() && report.code_names.boundaries.is_empty(),
        "an abstaining recovery must publish no offset-to-name pairs"
    );
    assert!(
        !report.code_names.reason.is_empty(),
        "the abstain must carry a named reason"
    );
    let lifted: AotLiftReport = lift_libapp_aot(&altered).expect("the lift must still report");
    assert_eq!(
        lifted.cluster_named_function_count, 0,
        "an unpinned version must contribute no cluster-derived names"
    );
}

#[test]
fn a_truncated_read_only_image_yields_a_typed_error_and_no_panic() {
    let bytes: Vec<u8> = fixture(SAMPLE);
    let full: DartGraphRecoveryReport =
        recover_dart_pinned_elf(&bytes, &DartGraphRecoveryOptions::default())
            .expect("baseline recovery");
    assert!(
        full.code_names.reason.is_empty(),
        "the unperturbed sample must decode its table, otherwise this case proves nothing"
    );

    let data_offset: usize = locate(&bytes, &[0xf5, 0xf5, 0xdc, 0xdc])
        .into_iter()
        .last()
        .expect("an isolate snapshot header must be present");
    for cut in [1_usize, 64, 4_096] {
        let mut truncated: Vec<u8> = bytes.clone();
        let end: usize = truncated.len();
        let from: usize = end.saturating_sub(cut);
        for byte in &mut truncated[from..end] {
            *byte = 0xFF;
        }
        let outcome: Result<DartGraphRecoveryReport, Error> =
            recover_dart_pinned_elf(&truncated, &DartGraphRecoveryOptions::default());
        match outcome {
            Ok(report) => assert!(
                report.code_names.reason.is_empty() || report.code_names.entries.is_empty(),
                "a corrupted tail must either decode cleanly or name a reason and publish nothing"
            ),
            Err(error) => {
                let rendered: String = error.to_string();
                assert!(
                    rendered.starts_with("DR-MOB-"),
                    "a corrupted image must fail with a typed diagnostic, got {rendered}"
                );
            }
        }
    }
    assert!(
        data_offset > 0,
        "the located isolate snapshot header must sit inside the image"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find_from(haystack, needle, 0).is_some()
}

fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
        .map(|at: usize| at + from)
}

fn locate(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut found: Vec<usize> = Vec::new();
    let mut at: usize = 0;
    while let Some(next) = find_from(haystack, needle, at) {
        found.push(next);
        at = next + 1;
    }
    found
}

#[test]
fn the_code_name_table_is_deterministic_and_sorted() {
    let bytes: Vec<u8> = fixture(SAMPLE);
    let first: DartGraphRecoveryReport =
        recover_dart_pinned_elf(&bytes, &DartGraphRecoveryOptions::default()).expect("first");
    let second: DartGraphRecoveryReport =
        recover_dart_pinned_elf(&bytes, &DartGraphRecoveryOptions::default()).expect("second");
    assert_eq!(
        first.code_names, second.code_names,
        "two recoveries of the same bytes must produce the same offset-to-name table"
    );
    assert!(
        first
            .code_names
            .entries
            .windows(2)
            .all(|pair: &[DartCodeName]| {
                (pair[0].instructions_offset, pair[0].qualified_name.as_str())
                    <= (pair[1].instructions_offset, pair[1].qualified_name.as_str())
            }),
        "the table must be emitted in a stable order so recovered source bytes never vary"
    );
}
