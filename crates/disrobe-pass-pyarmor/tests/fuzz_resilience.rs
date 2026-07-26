#![allow(clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_pass_pyarmor::static_unpack::bcdetect::detect_from_wrapper_text;
use disrobe_pass_pyarmor::static_unpack::{WrapperMagic, load_runtime_info, parse_header, sniff};
use disrobe_pass_pyarmor::{
    BccArch, ModeOverride, PyarmorCoDescriptor, PyarmorTrailer, StaticUnpackConfig,
    TargetPyVersion, UnpackOptions, classify_modes, classify_runtime_key, classify_serial,
    decode_mode_flags, detect_from_wrapper, detect_nine_pro, detect_sourcedefender_cross,
    format_python, lift_bcc_code_region, lift_bcc_native, parse_plaintext_xor_procedure,
    unpack_static, unpack_static_with_config, unpack_wrapper_text,
    unpack_wrapper_text_with_options,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const MAX_INPUT_BYTES: usize = 4096;
const RANDOM_SPAN_BYTES: usize = 4096;
const CASES_PER_INPUT: usize = 64;
const BATCH_SIZE: usize = 160;
const CASE_BUDGET: Duration = Duration::from_millis(400);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const SATURATION_DOMAIN: u64 = 0x5059_4152_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 2] = [(u8::MAX, 2), (0, 3)];
const MAX_SCATTERED_OVERWRITES: usize = 32;

const WRAPPER_TEXT: &[u8] = b"from pyarmor_runtime_000000 import __pyarmor__\n\
__pyarmor__(__name__, __file__, b'PY009000')\n";
const V8_HEADER_BYTES: usize = 64;
const V8_MAGIC: &[u8] = b"PY009000";
const WRAPPER_PATH: &str = "fuzz.py";
const ENTROPY_SPAN_SEED: u64 = 0x5059_4152_0001_0003;

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir.parent().and_then(Path::parent).expect(
        "the crate manifest directory has no workspace grandparent, so no corpus path exists",
    );
    workspace_root.join("corpus").join("python").join("pyarmor")
}

fn real_seed(parts: &[&str]) -> Vec<u8> {
    let source_path: PathBuf = parts
        .iter()
        .fold(corpus_root(), |root: PathBuf, part: &&str| root.join(part));
    let mut bytes: Vec<u8> = std::fs::read(&source_path).unwrap_or_else(|error| {
        panic!(
            "committed sample {} is unreadable: {error}",
            source_path.display()
        )
    });
    assert!(
        !bytes.is_empty(),
        "committed sample {} is empty, so this seed would silently stop exercising real input",
        source_path.display()
    );
    bytes.truncate(MAX_INPUT_BYTES);
    bytes
}

fn v8_header_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0u8; V8_HEADER_BYTES];
    if let Some(window) = bytes.get_mut(..V8_MAGIC.len()) {
        window.copy_from_slice(V8_MAGIC);
    }
    if let Some(window) = bytes.get_mut(28..32) {
        window.copy_from_slice(&u32::MAX.to_le_bytes());
    }
    if let Some(window) = bytes.get_mut(32..36) {
        window.copy_from_slice(&u32::MAX.to_le_bytes());
    }
    bytes
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("wrapper-text", WRAPPER_TEXT.to_vec()),
        CorpusEntry::new("v8-header", v8_header_seed()),
        CorpusEntry::new(
            "v8-basic-fluent-chain",
            real_seed(&[
                "v8",
                "basic",
                "chunk_16_modern_request_handler_fluent_chain_demo",
                "chunk_16_modern_request_handler_fluent_chain_demo.py",
            ]),
        ),
        CorpusEntry::new(
            "v9-themida-try-except",
            real_seed(&[
                "v9",
                "themida",
                "chunk_00_try_except_basic_try_except_else.py",
            ]),
        ),
        CorpusEntry::new(
            "v9-latest-known-plaintext",
            real_seed(&["v9_latest_925", "default", "known_plaintext.py"]),
        ),
        CorpusEntry::new(
            "v9-license-known-plaintext",
            real_seed(&["v9_license_id_015009", "default", "known_plaintext.py"]),
        ),
        CorpusEntry::new(
            "v9-themida-runtime-extension",
            real_seed(&[
                "v9",
                "themida",
                "pyarmor_runtime_000000",
                "pyarmor_runtime.pyd",
            ]),
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

fn consume<T>(_: T) {}

#[cfg(feature = "chain")]
fn exercise_chain_entrypoints(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::{DetectContext, Detector, ObfuscatorCatalog, Pass};
    use disrobe_pass_pyarmor::chain_detector::{PYARMOR_PASS, PyarmorDetector};

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let detector: PyarmorDetector = PyarmorDetector;
    consume(Detector::detect(&detector, &context));
    consume(ObfuscatorCatalog::detect(&detector, &context));
    consume(PYARMOR_PASS.run(&artifact));
    consume(PYARMOR_PASS.run_with_path(&artifact, Some(WRAPPER_PATH)));
    consume(PYARMOR_PASS.extract_children(&artifact));
}

fn probe(bytes: &[u8]) {
    let source: String = String::from_utf8_lossy(bytes).into_owned();
    let wrapper_path: &Path = Path::new(WRAPPER_PATH);
    let static_config: StaticUnpackConfig = StaticUnpackConfig {
        runtime_bytes: Some(bytes.to_vec()),
        ..StaticUnpackConfig::default()
    };
    let wrapper_options: UnpackOptions = UnpackOptions::default();
    consume(detect_from_wrapper(&source));
    consume(unpack_wrapper_text(&source, wrapper_path));
    consume(unpack_wrapper_text_with_options(
        &source,
        wrapper_path,
        &wrapper_options,
    ));
    consume(sniff(bytes));
    consume(detect_from_wrapper_text(&source));
    if let Ok(magic) = sniff(bytes) {
        consume(parse_header(bytes, magic));
    }
    consume(unpack_static(bytes));
    consume(unpack_static_with_config(bytes, &static_config));
    consume(load_runtime_info(bytes));
    consume(classify_modes(&source, bytes));
    consume(detect_nine_pro(bytes));
    consume(detect_sourcedefender_cross(
        &source,
        Some(wrapper_path),
        bytes,
    ));
    consume(format_python(&source));
    consume(decode_mode_flags(bytes));
    consume(classify_serial(&source));
    consume(classify_runtime_key(&source, bytes));
    consume(ModeOverride::parse(&source));
    consume(TargetPyVersion::parse(&source));
    consume(PyarmorCoDescriptor::parse(bytes));
    consume(PyarmorTrailer::parse(bytes));
    consume(parse_plaintext_xor_procedure(bytes));
    consume(lift_bcc_native(bytes, BccArch::WinX64));
    consume(lift_bcc_code_region(bytes, 0, BccArch::WinX64));
    #[cfg(feature = "chain")]
    exercise_chain_entrypoints(bytes);
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
fn the_constructed_v8_header_seed_sniffs_as_a_version_eight_or_nine_wrapper() {
    let magic: WrapperMagic = sniff(&v8_header_seed())
        .expect("the constructed header must sniff, or every header case is inert");
    assert_eq!(magic, WrapperMagic::Py8Or9);
}

#[test]
fn a_committed_sample_that_is_missing_fails_loudly() {
    let outcome: std::thread::Result<Vec<u8>> =
        std::panic::catch_unwind(|| real_seed(&["v9", "no-such-sample.py"]));
    assert!(
        outcome.is_err(),
        "a missing committed sample must abort the suite rather than yield an empty seed"
    );
}
