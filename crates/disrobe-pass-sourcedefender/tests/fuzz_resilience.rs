#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_core::provenance::ProvenanceHeader;
use disrobe_pass_sourcedefender::{
    ContainerVariant, DecoratorStripReport, DecryptedPye, DerivedKey, InlinedBlock,
    InlinedExtractOptions, InlinedExtraction, LayeredRecovery, ModernGcmFraming,
    ParsedPyeArrayEnvelope, PyeEnvelope, PyeFrame, Result, SourceRecoverOpts, SourceRecoverOutput,
    apply_aes_ctr, ascii85_decode, base85_decode_rfc1924, basename_of, classify_container,
    decode_armored_line, decrypt_frame, decrypt_modern_gcm_with_key, decrypt_pye,
    decrypt_pye_to_source, decrypt_pye_with_key, derive_aes_key, extract_inlined,
    frame_modern_gcm_body, hex_decode, hex_encode, locate_inlined_blocks, parse_array_envelope,
    parse_msgpack_envelope, parse_pye_frame, python_decoded_header, recover_from_marshal_bytes,
    recover_from_plaintext, recover_layered, recover_layered_with_modern_key,
    render_decoded_with_header, strip_extension, strip_sourcedefender_decorators,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 4096;
const ENTROPY_SPAN_SEED: u64 = 0x5344_4600_0001_0003;
const CASES_PER_INPUT: usize = 4096;
const BATCH_SIZE: usize = 2048;
const CASE_BUDGET: Duration = Duration::from_millis(10);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const PROBE_DOMAIN: u64 = 0x5344_465A_0001_0001;
const SATURATION_DOMAIN: u64 = 0x5344_465A_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 1] = [(u8::MAX, 2)];
const MAX_SCATTERED_OVERWRITES: usize = 32;
const KEY_BYTES: usize = 32;
const SOURCE_NAME: &str = "fuzz.pye";
const INLINED_NAME: &str = "fuzz.py";
const PYTHON_VERSION: &str = "3.14";
const HEADER_ELAPSED: Duration = Duration::from_millis(1);
const CONSTRUCTED_IV: [u8; 16] = [0xA5; 16];

fn legacy_frame_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"--BEGIN SOURCEDEFENDER FILE---\n");
    bytes.extend_from_slice(b"invalid-iv-armor\n");
    bytes.extend_from_slice(b"00000000000000000000000000000000\n");
    bytes.extend_from_slice(b"---END SOURCEDEFENDER FILE----\n");
    bytes
}

fn modern_frame_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"--BEGIN PYE FILE---\n");
    bytes.extend_from_slice(b"00112233445566778899AABBCCDDEEFF\n");
    bytes.extend_from_slice(b"---END PYE FILE----\n");
    bytes
}

fn msgpack_map_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(0xdf);
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    bytes
}

fn msgpack_array_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(0x91);
    bytes.push(0xc6);
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    bytes
}

fn msgpack_nesting_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend(std::iter::repeat_n(0x91u8, 96));
    bytes.push(0xc0);
    bytes
}

fn valid_msgpack_seed() -> Vec<u8> {
    let value: rmpv::Value = rmpv::Value::Map(vec![(
        rmpv::Value::String("original_code".into()),
        rmpv::Value::String("value = 1\n".into()),
    )]);
    let mut bytes: Vec<u8> = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .expect("a one-entry msgpack map encodes, and an empty seed would silently drop coverage");
    bytes
}

fn inlined_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"__sd_filename__ = 'fuzz'\n");
    bytes.extend_from_slice(b"--BEGIN SOURCEDEFENDER FILE---\n");
    bytes.extend_from_slice(b"armored-but-invalid\n");
    bytes.extend_from_slice(b"---END SOURCEDEFENDER FILE----\n");
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
        CorpusEntry::new("legacy-frame", legacy_frame_seed()),
        CorpusEntry::new("modern-frame", modern_frame_seed()),
        CorpusEntry::new("msgpack-map", msgpack_map_seed()),
        CorpusEntry::new("msgpack-array", msgpack_array_seed()),
        CorpusEntry::new("msgpack-nesting", msgpack_nesting_seed()),
        CorpusEntry::new("msgpack-valid", valid_msgpack_seed()),
        CorpusEntry::new("inlined", inlined_seed()),
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

fn exercise_byte_entrypoints(bytes: &[u8], rng: &mut XorShift64) {
    let mut key_bytes: [u8; KEY_BYTES] = [0u8; KEY_BYTES];
    for key_byte in &mut key_bytes {
        *key_byte = rng.next_byte();
    }
    let key: DerivedKey = DerivedKey(key_bytes);
    let options: SourceRecoverOpts = SourceRecoverOpts::default();
    let framing: ModernGcmFraming = frame_modern_gcm_body(bytes);
    let truncated: &[u8] = bytes
        .get(..bytes.len() / 2)
        .map_or(bytes, |slice: &[u8]| slice);

    let _: Result<Vec<u8>> = base85_decode_rfc1924(bytes);
    let _: Result<Vec<u8>> = ascii85_decode(bytes);
    let _: Result<Vec<u8>> = decode_armored_line(bytes);
    let _: Result<Vec<u8>> = hex_decode(bytes);
    let _: String = hex_encode(bytes);
    let _: Result<PyeEnvelope> = parse_msgpack_envelope(bytes);
    let _: Result<ParsedPyeArrayEnvelope> = parse_array_envelope(bytes);
    let _: Option<ContainerVariant> = classify_container(bytes);
    let _: Result<DecryptedPye> = decrypt_pye(bytes, SOURCE_NAME);
    let _: Result<DecryptedPye> = decrypt_pye_with_key(bytes, SOURCE_NAME, &key);
    let _: Result<Vec<u8>> = decrypt_modern_gcm_with_key(&framing, bytes, &key_bytes);
    let _: Result<Vec<u8>> = decrypt_modern_gcm_with_key(&framing, truncated, &key_bytes);
    let _: Result<LayeredRecovery> = recover_layered(bytes, SOURCE_NAME);
    let _: Result<LayeredRecovery> =
        recover_layered_with_modern_key(bytes, SOURCE_NAME, &key_bytes);
    let _: Result<SourceRecoverOutput> = decrypt_pye_to_source(bytes, SOURCE_NAME, options);
    let _: Result<SourceRecoverOutput> = recover_from_plaintext(bytes, None, options);
    let _: Result<SourceRecoverOutput> = recover_from_marshal_bytes(bytes, None, None, options);

    if let Ok(text) = core::str::from_utf8(bytes) {
        let _: Result<disrobe_pass_sourcedefender::PyeFrame> = parse_pye_frame(text);
        let _: Result<Vec<InlinedBlock>> = locate_inlined_blocks(text);
        let _: Result<InlinedExtraction> =
            extract_inlined(text, INLINED_NAME, InlinedExtractOptions::default());
        let _: Result<InlinedExtraction> = extract_inlined(
            text,
            INLINED_NAME,
            InlinedExtractOptions {
                require_known_basename: true,
            },
        );
        let _: DecoratorStripReport = strip_sourcedefender_decorators(text);
        let _: &str = basename_of(text);
        let _: &str = strip_extension(text);
        let _: Result<DerivedKey> = derive_aes_key(text);
        let _: String = render_decoded_with_header(text, HEADER_ELAPSED, PYTHON_VERSION);
        let _: ProvenanceHeader = python_decoded_header(HEADER_ELAPSED, PYTHON_VERSION);
    }
}

#[cfg(feature = "chain")]
fn exercise_chain_entrypoints(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::{DetectContext, Detector, Pass};
    use disrobe_pass_sourcedefender::chain_detector::{
        SOURCEDEFENDER_PASS, SourceDefenderDetector,
    };

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let _: Option<disrobe_core::chain::DetectVerdict> = SourceDefenderDetector.detect(&context);
    let _: disrobe_core::error::Result<Artifact> = SOURCEDEFENDER_PASS.run(&artifact);
    let _: disrobe_core::error::Result<Artifact> =
        SOURCEDEFENDER_PASS.run_with_path(&artifact, Some(SOURCE_NAME));
}

fn probe(bytes: &[u8], rng: &mut XorShift64) {
    exercise_byte_entrypoints(bytes, rng);
    #[cfg(feature = "chain")]
    exercise_chain_entrypoints(bytes);
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
fn malformed_length_markers_return_errors() {
    let legacy: Vec<u8> = legacy_frame_seed();
    let map: Vec<u8> = msgpack_map_seed();
    let array: Vec<u8> = msgpack_array_seed();
    let options: SourceRecoverOpts = SourceRecoverOpts::default();

    assert!(decode_armored_line(b"").is_err());
    assert!(parse_pye_frame("").is_err());
    assert!(parse_msgpack_envelope(&map).is_err());
    assert!(parse_array_envelope(&array).is_err());
    assert!(decrypt_pye(&legacy, SOURCE_NAME).is_err());
    assert!(recover_layered(&legacy, SOURCE_NAME).is_err());
    assert!(recover_from_marshal_bytes(&[], None, None, options).is_err());
}

#[test]
fn a_constructed_pye_frame_decrypts_and_recovers_its_source() {
    let key: DerivedKey = derive_aes_key("fuzz").expect("a passphrase derives an aes key");
    let mut ciphertext: Vec<u8> = valid_msgpack_seed();
    apply_aes_ctr(&mut ciphertext, key.as_bytes(), &CONSTRUCTED_IV);
    let frame: PyeFrame = PyeFrame {
        iv: CONSTRUCTED_IV,
        ciphertext,
    };
    let decrypted: DecryptedPye = decrypt_frame(&frame, &key, SOURCE_NAME);
    assert!(decrypted.envelope.is_some());
    let recovered: Result<SourceRecoverOutput> = recover_from_plaintext(
        &decrypted.plaintext_msgpack,
        decrypted.envelope.as_ref(),
        SourceRecoverOpts::default(),
    );
    assert!(recovered.is_ok());
}
