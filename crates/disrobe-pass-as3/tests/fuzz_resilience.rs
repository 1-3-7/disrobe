#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_pass_as3::abc;
use disrobe_pass_as3::swf;
use disrobe_testkit::{
    CorpusEntry, ReachTally, SeedReach, ShapelessSeed, StressCase, StressConfig, XorShift64,
};

const RANDOM_SPAN_BYTES: usize = 1024;
const CASES_PER_INPUT: usize = 8_704;
const BATCH_SIZE: usize = 4_352;
const CASE_BUDGET: Duration = Duration::from_millis(10);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const SATURATION_DOMAIN: u64 = 0x4153_3300_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 1] = [(u8::MAX, 2)];
const ENTROPY_SPAN_SEED: u64 = 0x4153_3300_0001_0003;

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

const ABC_CONSTANT_POOL_KINDS: usize = 7;

fn abc_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&abc::ABC_MINOR.to_le_bytes());
    bytes.extend_from_slice(&abc::ABC_MAJOR.to_le_bytes());
    bytes.extend(std::iter::repeat_n(0x00u8, ABC_CONSTANT_POOL_KINDS));
    bytes.push(0x01);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.push(0x00);
    bytes.push(0x00);
    bytes.push(0x01);
    bytes.extend_from_slice(&[0x00, 0x00]);
    bytes.push(0x00);
    bytes
}

fn swf_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"FWS");
    bytes.push(13);
    bytes.extend_from_slice(&64u32.to_le_bytes());
    bytes.resize(64, 0);
    bytes
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("abc-header", abc_seed()),
        CorpusEntry::new("swf-header", swf_seed()),
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

fn probe(bytes: &[u8]) {
    drop(measured_probe(bytes));
}

fn measured_probe(bytes: &[u8]) -> SeedReach {
    let mut reach: SeedReach = SeedReach::new();
    reach.record_result(
        "abc-constant-pool",
        &abc::parse(bytes),
        |file: &abc::AbcFile| {
            !file.methods.is_empty() || !file.scripts.is_empty() || !file.classes.is_empty()
        },
    );
    drop(abc::disasm(bytes));
    reach.drove();
    reach.record("swf-compression", swf::detect(bytes).is_some());
    reach.record_result("swf-tags", &swf::parse(bytes), |movie: &swf::Swf| {
        !movie.tags.is_empty()
    });
    reach
}

const SHAPELESS: [ShapelessSeed; 3] = [
    ShapelessSeed {
        name: "empty",
        reason: "the zero-length input every entry point must refuse rather than parse",
    },
    ShapelessSeed {
        name: "random-span",
        reason: "a kilobyte of zero bytes, present so the readers are driven over a buffer none of                  them can claim",
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
    println!("\n{}\n", tally.summary("as3"));
    tally.assert_every_seed_reaches("as3");
    assert_eq!(tally.total(), corpus().len());
}

fn check(case: &StressCase<'_>) {
    probe(case.bytes());
    probe(&saturate(case.bytes(), case.case_seed()));
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
fn every_unmutated_seed_finishes() {
    for entry in corpus() {
        probe(entry.bytes());
    }
}

#[test]
fn the_constructed_swf_seed_reads_as_an_uncompressed_swf() {
    let detection: Option<swf::SwfCompression> = swf::detect(&swf_seed());
    assert_eq!(detection, Some(swf::SwfCompression::None));
    let parsed: disrobe_pass_as3::Result<swf::Swf> = swf::parse(&swf_seed());
    assert!(
        parsed.is_ok(),
        "the constructed swf header must parse, or every swf-shaped case is inert: {parsed:?}"
    );
}
