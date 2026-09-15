#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_pass_nativelang::{analyze, demangle_crystal, demangle_d, demangle_nim, demangle_zig};
use disrobe_testkit::{
    CorpusEntry, ReachTally, SeedReach, ShapelessSeed, StressCase, StressConfig, XorShift64,
};

const RANDOM_SPAN_BYTES: usize = 1024;
const CASES_PER_INPUT: usize = 13_000;
const BATCH_SIZE: usize = 6_500;
const CASE_BUDGET: Duration = Duration::from_millis(20);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const SATURATION_DOMAIN: u64 = 0x4E47_4C41_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 1] = [(u8::MAX, 2)];
const MANGLED_DOMAIN: u64 = 0x4E47_4C41_0001_0003;
const MAX_MANGLED_BYTES: usize = 120;
const MANGLED_ALPHABET: &[u8] =
    b"_ZN0123456789abcdefghijklmnopqrstuvwxyzABCDEF$.@*<>,()[]\xc3\xa9\xf0\x9f\x98\x80";
const MANGLED_ALPHABET_SPARSITY: u32 = 2;

const MANGLED_SEED_TEXT: &[u8] = b"_ZN4test6methodEv\x00_D3std5stdio6printfFAyaZv\x00\
nimMain__abc_1\x00Sample::Type#method:Int32\x00example.module.function\x00";

const ENTROPY_SPAN_SEED: u64 = 0x4E47_4C41_0001_0004;

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

const ELF64_HEADER_LEN: usize = 64;
const ELF64_SECTION_HEADER_LEN: usize = 64;
const ELF64_SECTION_COUNT: usize = 2;
const ELF64_SHSTRTAB: &[u8] = b"\0.shstrtab\0";
const ZIG_RUNTIME_MARKER: &[u8] = b"__zig_probe_stack\0";

fn elf64_seed() -> Vec<u8> {
    let section_table: usize = ELF64_HEADER_LEN;
    let strtab_offset: usize = section_table + ELF64_SECTION_COUNT * ELF64_SECTION_HEADER_LEN;
    let mut bytes: Vec<u8> = vec![0u8; strtab_offset + ELF64_SHSTRTAB.len()];

    bytes[0..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&(section_table as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&(ELF64_HEADER_LEN as u16).to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&(ELF64_SECTION_HEADER_LEN as u16).to_le_bytes());
    bytes[60..62].copy_from_slice(&(ELF64_SECTION_COUNT as u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&1u16.to_le_bytes());

    let shstrtab: usize = section_table + ELF64_SECTION_HEADER_LEN;
    bytes[shstrtab..shstrtab + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[shstrtab + 4..shstrtab + 8].copy_from_slice(&3u32.to_le_bytes());
    bytes[shstrtab + 24..shstrtab + 32].copy_from_slice(&(strtab_offset as u64).to_le_bytes());
    bytes[shstrtab + 32..shstrtab + 40]
        .copy_from_slice(&(ELF64_SHSTRTAB.len() as u64).to_le_bytes());

    bytes[strtab_offset..].copy_from_slice(ELF64_SHSTRTAB);
    bytes.extend_from_slice(ZIG_RUNTIME_MARKER);
    bytes
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("zig-elf64", elf64_seed()),
        CorpusEntry::new("mangled-symbols", MANGLED_SEED_TEXT.to_vec()),
        CorpusEntry::new("random-span", vec![0u8; RANDOM_SPAN_BYTES]),
        CorpusEntry::new("entropy-span", entropy_span(RANDOM_SPAN_BYTES)),
    ]
}

fn saturate(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ SATURATION_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    let pick: usize = rng.below_usize(SATURATION_PATTERNS.len().saturating_add(1));
    let Some(&(value, sparsity)): Option<&(u8, u32)> = SATURATION_PATTERNS.get(pick) else {
        let changes: usize = rng.below_usize(out.len().saturating_add(1));
        for _ in 0..changes {
            let index: usize = rng.below_usize(out.len());
            if let Some(byte) = out.get_mut(index) {
                *byte = rng.next_byte();
            }
        }
        return out;
    };
    for byte in &mut out {
        if rng.next_u64().trailing_zeros() >= sparsity {
            *byte = value;
        }
    }
    out
}

fn mangled_from_seed(case_seed: u64) -> String {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ MANGLED_DOMAIN);
    let len: usize = rng.below_usize(MAX_MANGLED_BYTES);
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        if rng.next_u64().trailing_zeros() >= MANGLED_ALPHABET_SPARSITY {
            bytes.push(rng.next_byte());
        } else {
            let pick: usize = rng.below_usize(MANGLED_ALPHABET.len());
            bytes.push(MANGLED_ALPHABET.get(pick).copied().unwrap_or(b'_'));
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn probe_image(bytes: &[u8]) {
    drop(measured_probe(bytes));
}

fn measured_probe(bytes: &[u8]) -> SeedReach {
    let mut reach: SeedReach = SeedReach::new();
    reach.record_result(
        "native-image",
        &analyze(bytes),
        |report: &disrobe_pass_nativelang::NativeLangAnalysis| report.ptr_size > 0u8,
    );
    let text: String = String::from_utf8_lossy(bytes).into_owned();
    reach.record("nim-symbol", demangle_nim(&text).is_some());
    drop(demangle_zig(&text));
    reach.drove();
    reach.record("crystal-symbol", demangle_crystal(&text).is_some());
    reach.record("d-symbol", demangle_d(&text).is_some());
    reach
}

const SHAPELESS: [ShapelessSeed; 3] = [
    ShapelessSeed {
        name: "empty",
        reason: "the zero-length input every entry point must refuse rather than parse",
    },
    ShapelessSeed {
        name: "random-span",
        reason: "a kilobyte of zero bytes, present so the readers are driven over a buffer none of \
                 them can claim",
    },
    ShapelessSeed {
        name: "entropy-span",
        reason: "a pseudo-random span whose purpose is to be unparseable by every reader",
    },
];

#[test]
fn every_unmutated_seed_reaches_the_surface_it_is_named_for() {
    let mut tally: ReachTally = ReachTally::new();
    for entry in corpus() {
        let reach: SeedReach = measured_probe(entry.bytes());
        tally.observe(entry.name(), &reach, &SHAPELESS);
    }
    println!("\n{}\n", tally.summary("nativelang"));
    tally.assert_every_seed_reaches("nativelang");
    assert_eq!(tally.total(), corpus().len());
}

fn probe_symbol(text: &str) {
    let _ = demangle_nim(text);
    let _ = demangle_zig(text);
    let _ = demangle_crystal(text);
    let _ = demangle_d(text);
}

fn check(case: &StressCase<'_>) {
    probe_image(case.bytes());
    probe_image(&saturate(case.bytes(), case.case_seed()));
    probe_symbol(&String::from_utf8_lossy(case.bytes()));
    probe_symbol(&mangled_from_seed(case.case_seed()));
}

fn config() -> StressConfig {
    StressConfig {
        cases_per_input: CASES_PER_INPUT,
        batch_size: BATCH_SIZE,
        case_budget: CASE_BUDGET,
        suite_budget: SUITE_BUDGET,
        ..StressConfig::default()
    }
}

mod resilience {
    disrobe_testkit::stress_suite!(
        check: super::check,
        corpus: super::corpus,
        config: super::config
    );
}

#[test]
fn the_saturation_probe_rewrites_the_bytes_it_is_handed_and_replays_from_its_seed() {
    const SAMPLE: usize = 512;
    let original: Vec<u8> = vec![0x33u8; SAMPLE];
    let mut untouched: usize = 0;
    let mut distinct: Vec<Vec<u8>> = Vec::new();
    for case_seed in 0..SAMPLE as u64 {
        let probed: Vec<u8> = saturate(&original, case_seed);
        assert_eq!(probed, saturate(&original, case_seed));
        if probed == original {
            untouched = untouched.saturating_add(1);
        }
        if !distinct.contains(&probed) {
            distinct.push(probed);
        }
    }
    assert!(
        untouched < SAMPLE / 16,
        "{untouched} of {SAMPLE} probe outputs came back unchanged"
    );
    assert!(
        distinct.len() > SAMPLE / 2,
        "only {} distinct probe outputs",
        distinct.len()
    );
}

#[test]
fn the_mangled_symbol_probe_replays_from_its_seed_and_does_not_collapse() {
    const SAMPLE: u64 = 512;
    let mut distinct: Vec<String> = Vec::new();
    for case_seed in 0..SAMPLE {
        let text: String = mangled_from_seed(case_seed);
        assert_eq!(text, mangled_from_seed(case_seed));
        if !distinct.contains(&text) {
            distinct.push(text);
        }
    }
    assert!(
        distinct.len() > usize::try_from(SAMPLE).unwrap_or(usize::MAX) / 2,
        "only {} distinct mangled symbols",
        distinct.len()
    );
}

#[test]
fn every_unmutated_seed_finishes() {
    for entry in corpus() {
        probe_image(entry.bytes());
        probe_symbol(&String::from_utf8_lossy(entry.bytes()));
    }
}

#[test]
fn the_seeded_d_symbol_demangles_to_its_source_name() {
    let recovered: disrobe_pass_nativelang::DemangledSymbol =
        demangle_d("_D3std5stdio6printfFAyaZv")
            .expect("the committed mangled seed must demangle, or every symbol case is inert");
    assert_eq!(recovered.name, "printf");
    assert_eq!(recovered.module.as_deref(), Some("std.stdio"));
}
