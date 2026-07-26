#![allow(clippy::expect_used)]
use std::time::Duration;

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
use disrobe_pass_py_disasm::alt_runtimes::micropython::{parse as mpy_parse, parse_bytecode};
use disrobe_pass_py_disasm::alt_runtimes::micropython_native::parse as native_parse;
use disrobe_pass_py_disasm::alt_runtimes::pypy::parse as pypy_parse;
use disrobe_pass_py_disasm::alt_runtimes::recover::{recover, recover_detected};
use disrobe_pass_py_disasm::alt_runtimes::{AltRuntime, detect_runtime};
#[cfg(feature = "chain")]
use disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS;
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const MAX_INPUT_BYTES: usize = 4096;
const RANDOM_SPAN_BYTES: usize = 1024;
const CASES_PER_INPUT: usize = 10_240;
const BATCH_SIZE: usize = 5_120;
const CASE_BUDGET: Duration = Duration::from_millis(20);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const PERTURB_DOMAIN: u64 = 0x5044_4953_0001_0002;
const PERTURB_ARMS: usize = 3;
const MAX_SCATTERED_OVERWRITES: usize = 8;
const MAX_SELF_CONCATENATIONS: usize = 4;
const WORD_BYTES: usize = 4;
const ENTROPY_SPAN_SEED: u64 = 0x5044_4953_0001_0003;

const MICROPYTHON_BYTECODE: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy");
const PYPY_METHODS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/pypy/methods.pypy27.pyc");

const SEEDS: [(&str, &[u8]); 10] = [
    (
        "cpython-simple-const-3-11",
        include_bytes!("../../../corpus/python/decompile/legacy/compiled/simple_const.3.11.pyc"),
    ),
    (
        "cpython-simple-const-3-12",
        include_bytes!("../../../corpus/python/decompile/legacy/compiled/simple_const.3.12.pyc"),
    ),
    (
        "cpython-build-const-key-map-2-7",
        include_bytes!(
            "../../../corpus/python/decompile/legacy/compiled/build_const_key_map.2.7.pyc"
        ),
    ),
    (
        "cpython-binary-ops-3-11",
        include_bytes!("../../../corpus/python/decompile/legacy/compiled/binary_ops.3.11.pyc"),
    ),
    ("pypy-methods-2-7", PYPY_METHODS),
    (
        "pypy-hello-3-9-legacy",
        include_bytes!("../../../corpus/python/alt_runtimes/pypy/hello_pypy39_legacy.pypy39.pyc"),
    ),
    ("micropython-hello-bytecode", MICROPYTHON_BYTECODE),
    (
        "micropython-control-flow",
        include_bytes!("../../../corpus/python/alt_runtimes/micropython/control_flow.mpy"),
    ),
    (
        "micropython-native-x64",
        include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_x64.mpy"),
    ),
    (
        "micropython-native-armv7m",
        include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_armv7m.mpy"),
    ),
];

const RUNTIMES: [AltRuntime; 6] = [
    AltRuntime::PyPy,
    AltRuntime::MicroPython,
    AltRuntime::MicroPythonNative,
    AltRuntime::Jython,
    AltRuntime::IronPython,
    AltRuntime::Brython,
];

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn corpus() -> Vec<CorpusEntry> {
    let mut entries: Vec<CorpusEntry> = Vec::with_capacity(SEEDS.len().saturating_add(2));
    for (name, bytes) in SEEDS {
        assert!(
            !bytes.is_empty(),
            "committed seed `{name}` is empty, so this entry would silently stop exercising real input"
        );
        let bounded: usize = bytes.len().min(MAX_INPUT_BYTES);
        entries.push(CorpusEntry::new(
            name,
            bytes.get(..bounded).unwrap_or(bytes).to_vec(),
        ));
    }
    entries.push(CorpusEntry::new(
        "random-span",
        vec![0u8; RANDOM_SPAN_BYTES],
    ));
    entries.push(CorpusEntry::new(
        "entropy-span",
        entropy_span(RANDOM_SPAN_BYTES),
    ));
    entries
}

fn perturb(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ PERTURB_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    match rng.below_usize(PERTURB_ARMS) {
        0 => {
            let changes: usize = rng.below_usize(MAX_SCATTERED_OVERWRITES).saturating_add(1);
            for _ in 0..changes {
                let index: usize = rng.below_usize(out.len());
                if let Some(byte) = out.get_mut(index) {
                    *byte = rng.next_byte();
                }
            }
        }
        1 => {
            let copies: usize = rng.below_usize(MAX_SELF_CONCATENATIONS).saturating_add(1);
            let original: Vec<u8> = out.clone();
            for _ in 1..copies {
                if out.len().saturating_add(original.len()) > MAX_INPUT_BYTES {
                    break;
                }
                out.extend_from_slice(&original);
            }
        }
        _ => {
            let start: usize = rng.below_usize(out.len().saturating_add(1));
            let end: usize = start.saturating_add(WORD_BYTES);
            if let Some(window) = out.get_mut(start..end) {
                for slot in window {
                    *slot = rng.next_byte();
                }
            }
        }
    }
    out.truncate(MAX_INPUT_BYTES);
    out
}

fn probe(bytes: &[u8]) {
    let _: Option<AltRuntime> = detect_runtime(bytes);
    let _ = recover_detected(bytes);
    for runtime in RUNTIMES {
        let _ = recover(bytes, runtime);
    }
    let _ = mpy_parse(bytes);
    let _ = parse_bytecode(bytes);
    let _ = native_parse(bytes);
    if let Ok(module) = pypy_parse(bytes) {
        let _ = module.disassemble();
    }
    run_pass(bytes);
}

#[cfg(feature = "chain")]
fn run_pass(bytes: &[u8]) {
    let input: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let _ = PY_DISASM_PASS.run(&input);
}

#[cfg(not(feature = "chain"))]
const fn run_pass(_bytes: &[u8]) {}

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
        untouched < SAMPLE / 4,
        "{untouched} of {SAMPLE} probe outputs came back unchanged"
    );
    assert!(
        distinct.len() > SAMPLE / 4,
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
fn the_committed_alternate_runtime_seeds_are_detected_and_parse() {
    assert_eq!(
        detect_runtime(MICROPYTHON_BYTECODE),
        Some(AltRuntime::MicroPython)
    );
    assert!(
        mpy_parse(MICROPYTHON_BYTECODE).is_ok(),
        "the committed micropython seed must parse, or every mpy case is inert"
    );
    assert_eq!(detect_runtime(PYPY_METHODS), Some(AltRuntime::PyPy));
    assert!(
        pypy_parse(PYPY_METHODS).is_ok(),
        "the committed pypy seed must parse, or every pypy case is inert"
    );
}
