#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_pass_swift_objc::{
    analyze, decode_entitlements_from_code_signature, decode_entitlements_xml, extract_ipa,
    ipa_inventory, looks_like_swift_mangled, parse_info_plist, parse_slice, parse_swiftinterface,
    swift_demangle, walk_fat,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 1024;
const CASES_PER_INPUT: usize = 8_192;
const BATCH_SIZE: usize = 6_144;
const CASE_BUDGET: Duration = Duration::from_millis(20);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const SATURATION_DOMAIN: u64 = 0x5717_0B7C_0001_0002;
const SATURATION_ARMS: usize = 3;
const SATURATION_VALUE: u8 = u8::MAX;
const SATURATION_SPARSITY: u32 = 2;
const MAX_WORD_STAMPS: usize = 16;
const WORD_BYTES: usize = 4;

const MANGLED_DOMAIN: u64 = 0x5717_0B7C_0001_0003;
const MAX_MANGLED_BYTES: usize = 96;
const MANGLED_ALPHABET: &[u8] = b"$_TtSsViMNCPfgyz0123456789AaBbZ\xc3\xa9\xf0\x9f\x98\x80";
const MANGLED_ALPHABET_SPARSITY: u32 = 2;

const MANGLED_SEED_TEXT: &[u8] = b"$s5Hello5WorldC\x00$s3App4UserV\x00\
$s11SwiftDriver10ProcessSetC\x00$s10SwiftHello19LoginViewControllerCMn\x00";
const KNOWN_MANGLED_CLASS: &str = "$s5Hello5WorldC";

const ENTROPY_SPAN_SEED: u64 = 0x5717_0B7C_0001_0004;

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn macho64_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&0x0100_0007u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&72u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.resize(256, 0);
    bytes
}

fn fat_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
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

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("macho64-header", macho64_seed()),
        CorpusEntry::new("macho-fat-header", fat_seed()),
        CorpusEntry::new("zip-shell", zip_seed()),
        CorpusEntry::new("mangled-symbols", MANGLED_SEED_TEXT.to_vec()),
        CorpusEntry::new("random-span", vec![0u8; RANDOM_SPAN_BYTES]),
        CorpusEntry::new("entropy-span", entropy_span(RANDOM_SPAN_BYTES)),
    ]
}

fn saturate(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ SATURATION_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    match rng.below_usize(SATURATION_ARMS) {
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
            let stamps: usize = rng.below_usize(MAX_WORD_STAMPS);
            for _ in 0..stamps {
                let start: usize = rng.below_usize(out.len().saturating_add(1));
                let end: usize = start.saturating_add(WORD_BYTES);
                if let Some(window) = out.get_mut(start..end) {
                    window.copy_from_slice(&u32::MAX.to_le_bytes());
                }
            }
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
            bytes.push(MANGLED_ALPHABET.get(pick).copied().unwrap_or(b'$'));
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn probe_bytes(bytes: &[u8]) {
    let _ = analyze(bytes);
    let _ = walk_fat(bytes);
    if let Ok(parsed) = parse_slice(bytes) {
        let _ = disrobe_pass_swift_objc::symbol_names(bytes, &parsed);
    }
    let _ = extract_ipa(bytes);
    let _ = ipa_inventory(bytes);
    let _ = parse_info_plist(bytes);
    let _ = decode_entitlements_from_code_signature(bytes);
    let _ = decode_entitlements_xml(bytes);
    let _ = parse_swiftinterface(&String::from_utf8_lossy(bytes));
}

fn probe_symbol(text: &str) {
    let _ = swift_demangle(text);
    let _ = looks_like_swift_mangled(text);
}

fn check(case: &StressCase<'_>) {
    probe_bytes(case.bytes());
    probe_bytes(&saturate(case.bytes(), case.case_seed()));
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
        probe_bytes(entry.bytes());
        probe_symbol(&String::from_utf8_lossy(entry.bytes()));
    }
}

#[test]
fn the_seeded_swift_symbol_demangles_to_its_source_name() {
    assert!(looks_like_swift_mangled(KNOWN_MANGLED_CLASS));
    let recovered: String = swift_demangle(KNOWN_MANGLED_CLASS)
        .expect("the committed mangled seed must demangle, or every symbol case is inert");
    assert_eq!(recovered, "Hello.World (class)");
}
