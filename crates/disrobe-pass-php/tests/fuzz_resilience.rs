#![allow(clippy::expect_used)]
use std::time::Duration;

use disrobe_pass_php::bcompiler;
use disrobe_pass_php::decompile;
use disrobe_pass_php::encoder;
use disrobe_pass_php::protectors;
use disrobe_pass_php::{
    AesOutcome, AuthorizationToken, ContainerSurface, EncoderFamily, KeyScan, LoaderReport,
    OpArray, PeelOptions, PeelReport, PharArchive, PhpDetection, RecoveryReport, Result, build_cfg,
    decompile_oparray, deflatten, detect_php, extract_phar_entry, format_php, parse_oparray,
    parse_phar, peel_eval_chain, peel_modern_loader, recover_php, restructure,
    reverse_ioncube_container, reverse_sourceguardian_container, scan_key, signature_scan,
    surface_zend_guard, synthetic_transport_surface_ioncube,
    synthetic_transport_surface_sourceguardian, tokenize,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 4096;
const ENTROPY_SPAN_SEED: u64 = 0x5048_5000_0001_0003;
const CASES_PER_INPUT: usize = 96;
const BATCH_SIZE: usize = 320;
const CASE_BUDGET: Duration = Duration::from_millis(40);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const PROBE_DOMAIN: u64 = 0x5048_505F_0001_0001;
const SATURATION_DOMAIN: u64 = 0x5048_505F_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 1] = [(u8::MAX, 2)];
const MAX_SCATTERED_OVERWRITES: usize = 32;
const IV_BYTES: usize = 16;
const AES_KEY: &[u8] = b"0123456789abcdef";
const XOR_KEY: &[u8] = b"fuzz-key";
const MAX_ENVELOPE_STRINGS: usize = 32;
const IONCUBE_MARKER: &[u8] = b"<?php //004F\n";

fn phar_seed() -> Vec<u8> {
    let mut manifest: Vec<u8> = Vec::new();
    manifest.extend_from_slice(&0u32.to_le_bytes());
    manifest.extend_from_slice(&0x0011u16.to_be_bytes());
    manifest.extend_from_slice(&0u32.to_le_bytes());
    manifest.extend_from_slice(&0u32.to_le_bytes());
    manifest.extend_from_slice(&0u32.to_le_bytes());
    let mut bytes: Vec<u8> = b"<?php __HALT_COMPILER(); ?>".to_vec();
    let manifest_len: u32 = u32::try_from(manifest.len())
        .expect("the constructed phar manifest is a few dozen bytes long");
    bytes.extend_from_slice(&manifest_len.to_le_bytes());
    bytes.extend_from_slice(&manifest);
    bytes
}

fn bcg_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = b"BCG\x00".to_vec();
    bytes.push(8);
    bytes.push(0);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
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
        CorpusEntry::new(
            "clean-control",
            include_bytes!("fixtures/php_real_chains/clean_control.php").to_vec(),
        ),
        CorpusEntry::new(
            "double-base64-chain",
            include_bytes!("fixtures/php_real_chains/s_doubleb64.php").to_vec(),
        ),
        CorpusEntry::new(
            "protector-oparray",
            include_bytes!("fixtures/protector_oparray/hello.dzoa").to_vec(),
        ),
        CorpusEntry::new("phar-manifest", phar_seed()),
        CorpusEntry::new("bcompiler-header", bcg_seed()),
        CorpusEntry::new("ioncube-marker", b"<?php //004F\nAAAA\n".to_vec()),
        CorpusEntry::new(
            "sourceguardian-loader",
            b"<?php sg_load('AAAA');\n".to_vec(),
        ),
        CorpusEntry::new(
            "zend-guard-envelope",
            b"<?php @Zend;\n3\x00Zk3yZk3ypayload".to_vec(),
        ),
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
    let authorization: Option<AuthorizationToken> = Some(AuthorizationToken::user_attested());
    let mut iv: [u8; IV_BYTES] = [0u8; IV_BYTES];
    for byte in &mut iv {
        *byte = rng.next_byte();
    }
    let loader_key: u32 = u32::try_from(rng.next_u64() >> u32::BITS).unwrap_or(0);
    let source: String = String::from_utf8_lossy(bytes).into_owned();

    let _: Result<bcompiler::BcgHeader> = bcompiler::read_header(bytes);
    let parsed_oparray: Result<OpArray> = parse_oparray(bytes);
    if let Ok(oparray) = parsed_oparray {
        let _: disrobe_pass_php::Cfg = build_cfg(&oparray.ops);
        let _: disrobe_pass_php::Decompilation = decompile_oparray(&oparray);
    }
    let _: Result<OpArray> = decompile::parse_oparray(bytes);
    let _: PhpDetection = detect_php(bytes);
    let _: Result<disrobe_pass_php::DeflattenReport> = deflatten(bytes);
    let _: Result<disrobe_pass_php::RestructureReport> = restructure(bytes);
    let _: Result<Vec<disrobe_pass_php::Token<'_>>> = tokenize(bytes);
    let _: disrobe_pass_php::ScanReport = signature_scan(bytes);
    let _: Option<LoaderReport> = peel_modern_loader(bytes, loader_key);
    let _: Result<PeelReport> = peel_eval_chain(bytes, PeelOptions::default());
    let _: Result<RecoveryReport> = recover_php(bytes, authorization);
    let _: String = format_php(&source);

    for family in [
        EncoderFamily::IonCube,
        EncoderFamily::SourceGuardian,
        EncoderFamily::ZendGuard,
    ] {
        let _: KeyScan = scan_key(bytes, family);
    }
    let _: Vec<u8> = disrobe_pass_php::xor_decrypt(bytes, XOR_KEY);
    let _: AesOutcome = disrobe_pass_php::aes_cbc_decrypt(bytes, AES_KEY, &iv);

    let _: Option<encoder::EncoderDetection> = encoder::ioncube::detect(bytes);
    let _: Option<encoder::EncoderDetection> = encoder::sourceguardian::detect(bytes);
    let _: Option<encoder::EncoderDetection> = encoder::zend_guard::detect(bytes);
    let _: Result<encoder::DecodeOutcome> = encoder::ioncube::decode(bytes, authorization);
    let _: Result<encoder::DecodeOutcome> = encoder::sourceguardian::decode(bytes, authorization);
    let _: Result<encoder::DecodeOutcome> = encoder::zend_guard::decode(bytes, authorization);
    let _: Result<ContainerSurface> = reverse_ioncube_container(bytes, 0);
    let _: Result<ContainerSurface> = reverse_sourceguardian_container(bytes);
    let _: Result<ContainerSurface> = surface_zend_guard(bytes);
    let _: Result<ContainerSurface> = synthetic_transport_surface_ioncube(bytes, 0);
    let _: Result<ContainerSurface> = synthetic_transport_surface_sourceguardian(bytes);

    let _: Option<(protectors::ioncube::IonCubeEra, usize)> = protectors::ioncube::detect(bytes);
    let _: Option<usize> = protectors::ioncube::detect_loader_only(bytes);
    let _: Result<protectors::ProtectorDetection> = protectors::ioncube::analyze(bytes);
    let _: Option<(protectors::sourceguardian::SourceGuardianEra, usize)> =
        protectors::sourceguardian::detect(bytes);
    let _: Result<protectors::ProtectorDetection> = protectors::sourceguardian::analyze(bytes);
    let _: Option<(protectors::zend_guard::ZendGuardEra, usize, usize)> =
        protectors::zend_guard::detect(bytes);
    let _: Option<usize> = protectors::zend_guard::detect_loader_only(bytes);
    let _: Result<protectors::ProtectorDetection> = protectors::zend_guard::analyze(bytes);
    let _: Vec<String> =
        protectors::extract_envelope_strings(bytes, rng.below_usize(MAX_ENVELOPE_STRINGS));

    let parsed_phar: Result<PharArchive> = parse_phar(bytes);
    if let Ok(archive) = parsed_phar {
        let name: Option<&String> = archive.entries.keys().next();
        if let Some(name) = name {
            let _: Result<Vec<u8>> = extract_phar_entry(&archive, bytes, name);
        }
    }
}

#[cfg(feature = "chain")]
fn exercise_chain_entrypoints(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, Pass};
    use disrobe_pass_php::chain_detector::{PhpDetectorImpl, PhpPass};

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let detector: PhpDetectorImpl = PhpDetectorImpl;
    let pass: PhpPass = PhpPass;
    let _: Option<DetectVerdict> = detector.detect(&context);
    let _: disrobe_core::error::Result<Artifact> = pass.run(&artifact);
    let _: disrobe_core::error::Result<Vec<disrobe_core::chain::ChildArtifact>> =
        pass.extract_children(&artifact);
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
fn out_of_range_ioncube_marker_offsets_return_typed_errors() {
    let offset: usize = IONCUBE_MARKER.len().saturating_add(1);
    let reverse: Result<ContainerSurface> = reverse_ioncube_container(IONCUBE_MARKER, offset);
    let synthetic: Result<ContainerSurface> =
        synthetic_transport_surface_ioncube(IONCUBE_MARKER, offset);
    assert!(matches!(
        reverse,
        Err(disrobe_pass_php::Error::ContainerBadFraming {
            family: "ionCube",
            reason: "marker offset exceeds envelope length",
        })
    ));
    assert!(matches!(
        synthetic,
        Err(disrobe_pass_php::Error::ContainerBadFraming {
            family: "ionCube",
            reason: "marker offset exceeds envelope length",
        })
    ));
}
