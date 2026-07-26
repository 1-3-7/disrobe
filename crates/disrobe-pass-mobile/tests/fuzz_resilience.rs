#![allow(clippy::expect_used, clippy::panic)]
use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use disrobe_pass_mobile::apk_recon;
use disrobe_pass_mobile::arsc;
use disrobe_pass_mobile::axml;
use disrobe_pass_mobile::hermes;
use disrobe_pass_mobile::ios;
use disrobe_pass_mobile::react_native;
use disrobe_pass_mobile::xamarin;
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 1024;
const CASES_PER_INPUT: usize = 4_096;
const BATCH_SIZE: usize = 4_096;
const CASE_BUDGET: Duration = Duration::from_millis(20);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const PERTURB_DOMAIN: u64 = 0x4D4F_4249_0001_0002;
const PERTURB_ARMS: usize = 3;
const SATURATION_VALUE: u8 = u8::MAX;
const SATURATION_SPARSITY: u32 = 2;
const MAX_SCATTERED_INSERTS: usize = 48;
const ENTROPY_SPAN_SEED: u64 = 0x4D4F_4249_0001_0003;

const RICH_APK: &str = "corpus/apk/fixture-rich.apk";
const MANIFEST_ENTRY: &str = "AndroidManifest.xml";
const RESOURCES_ENTRY: &str = "resources.arsc";

fn axml_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0x0003u16.to_le_bytes());
    bytes.extend_from_slice(&0x0008u16.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0040u32.to_le_bytes());
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001cu16.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0030u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0002u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0000u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0100u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0000u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0028u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_002cu32.to_le_bytes());
    bytes.resize(0x40, 0);
    bytes
}

fn arsc_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0x0002u16.to_le_bytes());
    bytes.extend_from_slice(&0x000cu16.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0040u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0001u32.to_le_bytes());
    bytes.resize(0x40, 0);
    bytes
}

fn hermes_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&hermes::HERMES_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&96u32.to_le_bytes());
    bytes.resize(128, 0);
    bytes
}

fn zip_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"PK\x03\x04");
    bytes.extend_from_slice(&[0u8; 26]);
    bytes.extend_from_slice(b"PK\x05\x06");
    bytes.extend_from_slice(&[0u8; 18]);
    bytes
}

fn macho_fat_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 40]);
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

fn fixture_entry(relative: &str, name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push(relative);
    let archive_bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "committed fixture {} is unreadable: {error}",
            path.display()
        )
    });
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(archive_bytes);
    let mut archive: zip::ZipArchive<std::io::Cursor<Vec<u8>>> = zip::ZipArchive::new(cursor)
        .unwrap_or_else(|error| {
            panic!("committed fixture {} is not a zip: {error}", path.display())
        });
    let mut member: zip::read::ZipFile<'_> = archive
        .by_name(name)
        .unwrap_or_else(|error| panic!("fixture {} has no entry {name}: {error}", path.display()));
    let mut out: Vec<u8> = Vec::new();
    member
        .read_to_end(&mut out)
        .unwrap_or_else(|error| panic!("fixture entry {name} is unreadable: {error}"));
    assert!(
        !out.is_empty(),
        "fixture entry {name} is empty, so this seed would silently stop exercising real input"
    );
    out
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("axml-header", axml_seed()),
        CorpusEntry::new("arsc-header", arsc_seed()),
        CorpusEntry::new("hermes-header", hermes_seed()),
        CorpusEntry::new("zip-shell", zip_seed()),
        CorpusEntry::new("macho-fat-header", macho_fat_seed()),
        CorpusEntry::new(
            "apk-android-manifest",
            fixture_entry(RICH_APK, MANIFEST_ENTRY),
        ),
        CorpusEntry::new(
            "apk-resources-arsc",
            fixture_entry(RICH_APK, RESOURCES_ENTRY),
        ),
        CorpusEntry::new("random-span", vec![0u8; RANDOM_SPAN_BYTES]),
        CorpusEntry::new("entropy-span", entropy_span(RANDOM_SPAN_BYTES)),
    ]
}

fn perturb(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ PERTURB_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    match rng.below_usize(PERTURB_ARMS) {
        0 => {
            for byte in &mut out {
                if rng.next_u64().trailing_zeros() >= SATURATION_SPARSITY {
                    *byte = SATURATION_VALUE;
                }
            }
        }
        1 => {
            let changes: usize = rng.below_usize(out.len().saturating_add(1));
            for _ in 0..changes {
                let index: usize = rng.below_usize(out.len());
                if let Some(byte) = out.get_mut(index) {
                    *byte = rng.next_byte();
                }
            }
        }
        _ => {
            let at: usize = rng.below_usize(out.len().saturating_add(1));
            let inserts: usize = rng.below_usize(MAX_SCATTERED_INSERTS);
            for _ in 0..inserts {
                out.insert(at.min(out.len()), rng.next_byte());
            }
        }
    }
    out
}

fn probe(bytes: &[u8]) {
    let _ = axml::parse(bytes);
    let _ = arsc::parse(bytes);
    let _ = hermes::parse_header(bytes);
    let _ = hermes::parse(bytes);
    let _ = apk_recon::analyze(bytes);
    let _ = ios::walk_macho_fat(bytes);
    let _ = ios::extract_ipa(bytes);
    let _ = xamarin::parse_assembly_store_header(bytes);
    let _ = xamarin::extract_xamarin_bundle(bytes);
    let _ = react_native::detect_bundle_format(bytes);
    let _ = react_native::extract_from_apk_or_ipa(bytes);
}

fn check(case: &StressCase<'_>) {
    probe(case.bytes());
    probe(&perturb(case.bytes(), case.case_seed()));
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
fn the_second_probe_rewrites_the_bytes_it_is_handed_and_replays_from_its_seed() {
    const SAMPLE: usize = 512;
    let original: Vec<u8> = vec![0x33u8; SAMPLE];
    let mut untouched: usize = 0;
    let mut distinct: Vec<Vec<u8>> = Vec::new();
    for case_seed in 0..SAMPLE as u64 {
        let probed: Vec<u8> = perturb(&original, case_seed);
        assert_eq!(probed, perturb(&original, case_seed));
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
fn the_committed_apk_fixture_entries_parse_as_the_formats_they_seed() {
    let manifest: Vec<u8> = fixture_entry(RICH_APK, MANIFEST_ENTRY);
    let document: axml::AxmlDocument = axml::parse(&manifest)
        .expect("the committed binary manifest must parse, or every axml case is inert");
    assert_eq!(document.root.name, "manifest");

    let resources: Vec<u8> = fixture_entry(RICH_APK, RESOURCES_ENTRY);
    let table: arsc::ArscResources = arsc::parse(&resources)
        .expect("the committed resource table must parse, or every arsc case is inert");
    assert!(!table.packages.is_empty());
}

#[test]
fn a_fixture_path_that_does_not_exist_fails_loudly() {
    let outcome: std::thread::Result<Vec<u8>> = std::panic::catch_unwind(|| {
        fixture_entry("corpus/apk/no-such-fixture.apk", MANIFEST_ENTRY)
    });
    assert!(
        outcome.is_err(),
        "a missing fixture must abort the suite rather than yield an empty seed"
    );
}

#[test]
fn a_fixture_entry_that_does_not_exist_fails_loudly() {
    let outcome: std::thread::Result<Vec<u8>> =
        std::panic::catch_unwind(|| fixture_entry(RICH_APK, "no-such-entry"));
    assert!(
        outcome.is_err(),
        "a missing archive member must abort the suite rather than yield an empty seed"
    );
}

#[test]
fn a_deeply_nested_axml_chunk_chain_does_not_overflow_the_stack() {
    for depth in [64usize, 1_024, 16_384] {
        let mut bytes: Vec<u8> = Vec::with_capacity(depth.saturating_mul(8));
        for _ in 0..depth {
            bytes.extend_from_slice(&0x0102u16.to_le_bytes());
            bytes.extend_from_slice(&0x0008u16.to_le_bytes());
            bytes.extend_from_slice(&0x0000_0008u32.to_le_bytes());
        }
        let _ = axml::parse(&bytes);
        let _ = arsc::parse(&bytes);
    }
}
