#![allow(clippy::expect_used)]
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_pass_py_deob::{
    ast_eval, auto_deobfuscate, cleanup_source, decode_hyperion_v2v3_inner,
    decode_hyperion_v2v3_inner_with_version, detect, detect_hyperion_v2v3, detect_marshal,
    format_python, iter_passes, looks_obfuscated, peel, peel_hyperion_v2v3_all_layers,
    peel_hyperion_v2v3_layer, peel_with_pyver, recover_marshal_source, recover_pyc_zipper,
    unidentified_guidance,
};
use disrobe_py_marshal::PyVersion;
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, StressError, XorShift64};

const RANDOM_SPAN_BYTES: usize = 4096;
const ENTROPY_SPAN_SEED: u64 = 0x5044_4542_0001_0003;
const SEED_BYTE_LIMIT: usize = 4096;
const CASES_PER_INPUT: usize = 24;
const BATCH_SIZE: usize = 72;
const CASE_BUDGET: Duration = Duration::from_millis(400);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const SATURATION_DOMAIN: u64 = 0x5059_4445_4F42_0002;
const SATURATION_PATTERNS: [(u8, u32); 2] = [(u8::MAX, 2), (0, 3)];
const MAX_SCATTERED_OVERWRITES: usize = 32;
const HYPERION_LAYER_LIMIT: usize = 8;

const REAL_SAMPLES: [(&str, &[&str]); 4] = [
    ("berserker", &["berserker", "real_sample.py"]),
    ("blankobf", &["blankobf", "real_edge_cases_3_8_r1.py"]),
    ("kramer", &["kramer", "gauntlet", "real_gauntlet_kramer.py"]),
    ("patchwork", &["patchwork", "real_hello_world.py"]),
];

fn corpus_root() -> Result<PathBuf, StressError> {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| StressError::Inconsistent {
            detail: format!(
                "{} has no grandparent, so the corpus directory cannot be located",
                manifest_dir.display()
            ),
        })?;
    Ok(workspace_root
        .join("corpus")
        .join("python")
        .join("obfuscators"))
}

fn real_sample(parts: &[&str]) -> Result<Vec<u8>, StressError> {
    let path: PathBuf = parts
        .iter()
        .fold(corpus_root()?, |root: PathBuf, part: &&str| root.join(part));
    let mut bytes: Vec<u8> =
        std::fs::read(&path).map_err(|error: std::io::Error| StressError::Io {
            context: format!("reading the obfuscator sample {}", path.display()),
            source: error,
        })?;
    if bytes.is_empty() {
        return Err(StressError::Inconsistent {
            detail: format!(
                "the obfuscator sample {} is empty, so it would contribute no coverage",
                path.display()
            ),
        });
    }
    bytes.truncate(SEED_BYTE_LIMIT);
    Ok(bytes)
}

fn pyc_header_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0u8; 16];
    bytes
        .get_mut(..4)
        .expect("a sixteen byte buffer holds a four byte magic")
        .copy_from_slice(&[0x50, 0x0d, 0x0d, 0x0a]);
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

fn corpus() -> Result<Vec<CorpusEntry>, StressError> {
    let mut entries: Vec<CorpusEntry> = vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("plain-source", b"print('fuzz')\n".to_vec()),
        CorpusEntry::new(
            "marshal-exec",
            b"exec(marshal.loads(b'\\xff\\xff\\xff\\xff'))\n".to_vec(),
        ),
        CorpusEntry::new("pyc-header", pyc_header_seed()),
    ];
    for (name, parts) in REAL_SAMPLES {
        entries.push(CorpusEntry::new(name, real_sample(parts)?));
    }
    entries.push(CorpusEntry::new(
        "random-span",
        vec![0u8; RANDOM_SPAN_BYTES],
    ));
    entries.push(CorpusEntry::new(
        "entropy-span",
        entropy_span(RANDOM_SPAN_BYTES),
    ));
    Ok(entries)
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
    use disrobe_pass_py_deob::chain_detector::{PY_DEOB_PASS, PyDeobDetector};

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let detector: PyDeobDetector = PyDeobDetector;
    consume(Detector::detect(&detector, &context));
    consume(ObfuscatorCatalog::detect(&detector, &context));
    consume(PY_DEOB_PASS.run(&artifact));
    consume(PY_DEOB_PASS.extract_children(&artifact));
}

fn exercise_byte_entrypoints(bytes: &[u8]) {
    let source: String = String::from_utf8_lossy(bytes).into_owned();
    consume(detect(bytes));
    consume(auto_deobfuscate(bytes, None));
    consume(looks_obfuscated(bytes));
    consume(unidentified_guidance(bytes));
    consume(peel(bytes));
    consume(peel_with_pyver(bytes, None));
    consume(detect_hyperion_v2v3(bytes));
    consume(peel_hyperion_v2v3_all_layers(bytes, HYPERION_LAYER_LIMIT));
    consume(peel_hyperion_v2v3_layer(bytes));
    consume(decode_hyperion_v2v3_inner(bytes));
    consume(decode_hyperion_v2v3_inner_with_version(
        bytes,
        PyVersion::PY311,
    ));
    consume(detect_marshal(bytes));
    consume(recover_marshal_source(bytes, None));
    consume(recover_pyc_zipper(bytes));
    consume(cleanup_source(&source));
    consume(ast_eval::evaluate_source(&source));
    consume(format_python(&source));
    consume(disrobe_pass_py_deob::obfuscators::kramer::try_recover_payload_bytes(bytes));
    let report: disrobe_pass_py_deob::obfuscators::pyminifier_variants::VariantReport =
        disrobe_pass_py_deob::obfuscators::pyminifier_variants::classify(&source);
    consume(
        disrobe_pass_py_deob::obfuscators::pyminifier_variants::decompress(&source, report.kind),
    );
    for pass in iter_passes() {
        consume(pass.detect(bytes));
        consume(pass.peel(bytes));
    }
}

fn probe(bytes: &[u8]) {
    exercise_byte_entrypoints(bytes);
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
    for entry in corpus().expect("the corpus builds") {
        probe(entry.bytes());
    }
}

#[test]
fn every_real_obfuscator_sample_is_present_and_carries_bytes() {
    let entries: Vec<CorpusEntry> = corpus().expect("the corpus builds");
    for (name, _) in REAL_SAMPLES {
        let entry: &CorpusEntry = entries
            .iter()
            .find(|entry: &&CorpusEntry| entry.name() == name)
            .expect("every named real sample reaches the corpus");
        assert!(
            !entry.bytes().is_empty(),
            "the {name} sample contributed no bytes"
        );
        assert!(entry.bytes().len() <= SEED_BYTE_LIMIT);
    }
}

#[test]
fn a_missing_obfuscator_sample_fails_loudly_rather_than_yielding_an_empty_seed() {
    let missing: Result<Vec<u8>, StressError> =
        real_sample(&["berserker", "no_such_sample_on_disk.py"]);
    let error: StressError = missing.expect_err("a missing sample must not read as empty bytes");
    assert!(
        matches!(error, StressError::Io { .. }),
        "unexpected refusal: {error}"
    );
}
