#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_pass_pyinstaller::{
    Cookie, MEI_MAGIC, TocEntry, extract_archive, extract_pyz, find_cookie, walk_toc,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

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

fn pyz_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"PYZ\x00");
    bytes.extend_from_slice(&0x0a0du32.to_be_bytes());
    bytes.extend_from_slice(&64u32.to_be_bytes());
    bytes.resize(64, 0);
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
    if let Ok(cookie) = find_cookie(bytes) {
        let _ = walk_toc(bytes, &cookie);
    }
    let _ = extract_archive(bytes);
    let _ = extract_pyz(bytes);
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
