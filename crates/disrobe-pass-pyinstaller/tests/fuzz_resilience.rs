#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_pass_pyinstaller::{
    Cookie, MEI_MAGIC, PyzEntry, TocEntry, extract_archive, extract_pyz, find_cookie, walk_toc,
};
use disrobe_py_marshal::PyVersion;
use disrobe_testkit::{
    CorpusEntry, ReachTally, SeedReach, ShapelessSeed, StressCase, StressConfig, XorShift64,
};

const MEI_PYZ_MAGIC: &[u8; 4] = b"PYZ\0";
const RANDOM_SPAN_BYTES: usize = 1024;
const CASES_PER_INPUT: usize = 11_264;
const BATCH_SIZE: usize = 5_632;
const CASE_BUDGET: Duration = Duration::from_millis(10);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const SATURATION_DOMAIN: u64 = 0x5049_4E53_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 2] = [(u8::MAX, 2), (0, 3)];

const COOKIE_TAIL_BYTES: u32 = 88;
const SEED_ENTRY_NAME: &[u8] = b"entry\x00\x00\x00";
const SEED_ENTRY_FIXED_BYTES: u32 = 18;
const SEED_PAYLOAD: &[u8] = b"DATA";
const SEED_PYVER: u32 = 311;
const SEED_LIBNAME_BYTES: usize = 64;
const ENTROPY_SPAN_SEED: u64 = 0x5049_4E53_0001_0003;

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn pyinstaller_seed() -> Vec<u8> {
    let mut toc: Vec<u8> = Vec::new();
    let name_len: u32 = u32::try_from(SEED_ENTRY_NAME.len())
        .expect("the constructed table-of-contents name is eight bytes long");
    let entry_size: u32 = SEED_ENTRY_FIXED_BYTES.saturating_add(name_len);
    toc.extend_from_slice(&entry_size.to_be_bytes());
    toc.extend_from_slice(&0u32.to_be_bytes());
    toc.extend_from_slice(&4u32.to_be_bytes());
    toc.extend_from_slice(&4u32.to_be_bytes());
    toc.push(0);
    toc.push(b'b');
    toc.extend_from_slice(SEED_ENTRY_NAME);

    let mut image: Vec<u8> = Vec::new();
    image.extend_from_slice(SEED_PAYLOAD);
    let toc_offset: u32 = u32::try_from(image.len())
        .expect("the constructed archive payload is a handful of bytes long");
    image.extend_from_slice(&toc);
    let toc_length: u32 =
        u32::try_from(toc.len()).expect("the constructed table of contents is one short entry");

    let cookie_offset: u32 = u32::try_from(image.len())
        .expect("the constructed archive stays far inside the 32-bit offset range");
    image.extend_from_slice(MEI_MAGIC);
    image.extend_from_slice(
        &cookie_offset
            .saturating_add(COOKIE_TAIL_BYTES)
            .to_be_bytes(),
    );
    image.extend_from_slice(&toc_offset.to_be_bytes());
    image.extend_from_slice(&toc_length.to_be_bytes());
    image.extend_from_slice(&SEED_PYVER.to_be_bytes());
    let mut libname: Vec<u8> = b"python3.11".to_vec();
    libname.resize(SEED_LIBNAME_BYTES, 0);
    image.extend_from_slice(&libname);
    image
}

const PYZ_PYC_MAGIC_PY37: u32 = 0x0a0d_0d42;
const PYZ_HEADER_LEN: usize = 12;
const PYZ_MODULE_NAME: &[u8] = b"seedmod";
const PYZ_ZLIB_PAYLOAD: [u8; 14] = [
    0x78, 0xda, 0x4b, 0x61, 0x60, 0x60, 0x08, 0x66, 0x00, 0x00, 0x03, 0x04, 0x00, 0xb8,
];

fn marshal_tuple_header(out: &mut Vec<u8>, count: u32) {
    out.push(b'(');
    out.extend_from_slice(&count.to_le_bytes());
}

fn marshal_int(out: &mut Vec<u8>, value: i32) {
    out.push(b'i');
    out.extend_from_slice(&value.to_le_bytes());
}

fn marshal_string(out: &mut Vec<u8>, value: &[u8]) {
    out.push(b's');
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn pyz_seed() -> Vec<u8> {
    let payload_offset: usize = PYZ_HEADER_LEN;
    let toc_offset: usize = payload_offset + PYZ_ZLIB_PAYLOAD.len();

    let mut toc: Vec<u8> = Vec::new();
    marshal_tuple_header(&mut toc, 1);
    marshal_tuple_header(&mut toc, 2);
    marshal_string(&mut toc, PYZ_MODULE_NAME);
    marshal_tuple_header(&mut toc, 3);
    marshal_int(&mut toc, 0);
    marshal_int(&mut toc, payload_offset as i32);
    marshal_int(&mut toc, PYZ_ZLIB_PAYLOAD.len() as i32);

    let mut bytes: Vec<u8> = Vec::with_capacity(toc_offset + toc.len());
    bytes.extend_from_slice(MEI_PYZ_MAGIC);
    bytes.extend_from_slice(&PYZ_PYC_MAGIC_PY37.to_le_bytes());
    bytes.extend_from_slice(&(toc_offset as u32).to_be_bytes());
    bytes.extend_from_slice(&PYZ_ZLIB_PAYLOAD);
    bytes.extend_from_slice(&toc);
    bytes
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("carchive-cookie", pyinstaller_seed()),
        CorpusEntry::new("pyz-header", pyz_seed()),
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
    match find_cookie(bytes) {
        Ok(cookie) => reach.record_result(
            "carchive-toc",
            &walk_toc(bytes, &cookie),
            |entries: &Vec<TocEntry>| !entries.is_empty(),
        ),
        Err(_) => reach.drove(),
    }
    reach.record_result(
        "carchive-entries",
        &extract_archive(bytes),
        |output: &disrobe_pass_pyinstaller::ExtractOutput| !output.entries.is_empty(),
    );
    reach.record_result(
        "pyz-modules",
        &extract_pyz(bytes),
        |(_, entries): &(PyVersion, Vec<PyzEntry>)| !entries.is_empty(),
    );
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
    println!("\n{}\n", tally.summary("pyinstaller"));
    tally.assert_every_seed_reaches("pyinstaller");
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
fn the_constructed_carchive_seed_walks_its_one_table_of_contents_entry() {
    let image: Vec<u8> = pyinstaller_seed();
    let cookie: Cookie = find_cookie(&image)
        .expect("the constructed cookie must be located, or every carchive case is inert");
    assert_eq!(cookie.python_major, 3);
    assert_eq!(cookie.python_minor, 11);
    let entries: Vec<TocEntry> =
        walk_toc(&image, &cookie).expect("the constructed table of contents must walk");
    assert_eq!(entries.len(), 1);
    let entry: &TocEntry = entries
        .first()
        .expect("a one-entry table of contents yields a first entry");
    assert_eq!(entry.name, "entry");
}
