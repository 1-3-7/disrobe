#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_pass_webview::{
    CarveConfig, CarveReport, RecoveredAsset, Result, WebviewFamily, carve, carve_report,
    carve_with_config, detect_family,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 4096;
const ENTROPY_SPAN_SEED: u64 = 0x5745_4256_0001_0003;
const CASES_PER_INPUT: usize = 512;
const BATCH_SIZE: usize = 1024;
const CASE_BUDGET: Duration = Duration::from_millis(20);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const PROBE_DOMAIN: u64 = 0x5745_4256_0001_0001;
const SATURATION_DOMAIN: u64 = 0x5745_4256_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 1] = [(u8::MAX, 2)];
const MAX_SCATTERED_OVERWRITES: usize = 32;
const MAX_SCAN_CANDIDATES: usize = 64;
const MAX_CARVE_DEPTH: usize = 128;
const MAX_TABLE_PROBES: u64 = 100_000;
const ASAR_ALIGNMENT: u32 = 4;

fn asar_seed() -> Vec<u8> {
    let json: &[u8] = br#"{"files":{"index.html":{"size":2,"offset":"0"}}}"#;
    let json_len: u32 =
        u32::try_from(json.len()).expect("the constructed asar header is a few dozen bytes long");
    let aligned: u32 = json_len.div_ceil(ASAR_ALIGNMENT) * ASAR_ALIGNMENT;
    let payload_size: u32 = aligned + ASAR_ALIGNMENT;
    let header_buf_len: u32 = payload_size + ASAR_ALIGNMENT;
    let padding: usize = usize::try_from(aligned - json_len)
        .expect("the alignment padding is smaller than the alignment itself");
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&ASAR_ALIGNMENT.to_le_bytes());
    bytes.extend_from_slice(&header_buf_len.to_le_bytes());
    bytes.extend_from_slice(&payload_size.to_le_bytes());
    bytes.extend_from_slice(&json_len.to_le_bytes());
    bytes.extend_from_slice(json);
    bytes.extend(std::iter::repeat_n(0u8, padding));
    bytes.extend_from_slice(b"ok");
    bytes
}

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("asar-archive", asar_seed()),
        CorpusEntry::new("tauri-marker", b"tauri://localhost".to_vec()),
        CorpusEntry::new("wails-marker", b"wails://runtime".to_vec()),
        CorpusEntry::new(
            "elf-header",
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        ),
        CorpusEntry::new("truncated-asar-json", b"{\"files\":\"truncated".to_vec()),
        CorpusEntry::new("random-span", vec![0u8; RANDOM_SPAN_BYTES]),
        CorpusEntry::new("entropy-span", entropy_span(RANDOM_SPAN_BYTES)),
    ]
}

fn saturate(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ SATURATION_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    let pick: usize = rng.below_usize(SATURATION_PATTERNS.len().saturating_add(1));
    let Some(&(value, sparsity)): Option<&(u8, u32)> = SATURATION_PATTERNS.get(pick) else {
        let changes: usize = rng.below_usize(MAX_SCATTERED_OVERWRITES);
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

fn probe(bytes: &[u8], rng: &mut XorShift64) {
    let config: CarveConfig = CarveConfig {
        max_scan_candidates: rng.below_usize(MAX_SCAN_CANDIDATES),
        max_depth: rng.below_usize(MAX_CARVE_DEPTH),
        max_table_probes: rng.below(MAX_TABLE_PROBES),
        ..CarveConfig::default()
    };

    let _: Option<WebviewFamily> = detect_family(bytes);
    let _: Result<Vec<RecoveredAsset>> = carve(bytes);
    let _: Result<CarveReport> = carve_report(bytes);
    let _: Result<CarveReport> = carve_with_config(bytes, &config);
}

fn check(case: &StressCase<'_>) {
    let mut rng: XorShift64 = XorShift64::new(case.case_seed() ^ PROBE_DOMAIN);
    probe(case.bytes(), &mut rng);
    probe(&saturate(case.bytes(), case.case_seed()), &mut rng);
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
        let mut rng: XorShift64 = XorShift64::new(PROBE_DOMAIN);
        probe(entry.bytes(), &mut rng);
    }
}

#[test]
fn the_constructed_asar_seed_carves_its_one_stored_asset() {
    let assets: Vec<RecoveredAsset> =
        carve(&asar_seed()).expect("the constructed asar header parses");
    assert_eq!(assets.len(), 1);
    let asset: &RecoveredAsset = assets
        .first()
        .expect("a one-asset carve yields a first asset");
    assert_eq!(asset.path, "index.html");
    assert_eq!(asset.bytes, b"ok");
}
