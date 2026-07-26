#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::time::Duration;

use disrobe_py_marshal::{
    Object, PyVersion, RefTableDump, dump_reftable, load, load_with_reftable, read_pyc,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const VERSIONS: [PyVersion; 4] = [
    PyVersion::PY15,
    PyVersion::PY27,
    PyVersion::PY37,
    PyVersion {
        major: 3,
        minor: 11,
    },
];

const RANDOM_SPAN_BYTES: usize = 1024;
const ENTROPY_SPAN_SEED: u64 = 0x5041_5253_0001_0003;
const CASES_PER_INPUT: usize = 10_000;
const BATCH_SIZE: usize = 3_000;
const CASE_BUDGET: Duration = Duration::from_millis(5);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const COLLECTION_TAGS: [u8; 6] = [b'(', b'[', b'{', b'<', b'>', b'c'];
const RETAG_DOMAIN: u64 = 0x5265_5461_6721_0001;
const RETAG_SPARSITY: u32 = 3;

fn marshal_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.push(b'(');
    v.extend_from_slice(&3u32.to_le_bytes());
    v.push(b'i');
    v.extend_from_slice(&7i32.to_le_bytes());
    v.push(b's');
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(b"hi");
    v.push(b'N');
    v
}

fn pyc_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0x0a0d_0d33u32.to_le_bytes());
    v.extend_from_slice(&[0u8; 12]);
    v.extend_from_slice(&marshal_seed());
    v
}

fn nested_collection_bomb(depth: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(depth * 5);
    for _ in 0..depth {
        v.push(b'(');
        v.extend_from_slice(&1u32.to_le_bytes());
    }
    v.push(b'N');
    v
}

fn retag_collections(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ RETAG_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    let tags: u64 = COLLECTION_TAGS.len() as u64;
    for byte in &mut out {
        if rng.next_u64().trailing_zeros() >= RETAG_SPARSITY {
            let pick: usize = usize::try_from(rng.below(tags)).unwrap_or(0);
            if let Some(tag) = COLLECTION_TAGS.get(pick) {
                *byte = *tag;
            }
        }
    }
    out
}

fn probe(bytes: &[u8]) {
    let _ = read_pyc(bytes);
    for version in VERSIONS {
        let _ = load(bytes, version);
        let _ = load_with_reftable(bytes, version);
        let _ = dump_reftable(bytes, version);
    }
}

fn check(case: &StressCase<'_>) {
    probe(case.bytes());
    probe(&retag_collections(case.bytes(), case.case_seed()));
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
        CorpusEntry::new("marshal-tuple", marshal_seed()),
        CorpusEntry::new("pyc-header", pyc_seed()),
        CorpusEntry::new("random-span", vec![0u8; RANDOM_SPAN_BYTES]),
        CorpusEntry::new("entropy-span", entropy_span(RANDOM_SPAN_BYTES)),
    ]
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
fn deep_nesting_does_not_overflow_stack() {
    for depth in [64usize, 255, 256, 257, 1_000, 100_000, 5_000_000] {
        let bomb: Vec<u8> = nested_collection_bomb(depth);
        for version in VERSIONS {
            let _ = load(&bomb, version);
        }
        let _ = read_pyc(&bomb);
    }
}

#[test]
fn a_module_scale_interned_string_count_is_accepted() {
    const INTERNED: usize = 6_000;
    let mut data: Vec<u8> = Vec::with_capacity(INTERNED * 5 + 5);
    data.push(b'(');
    data.extend(u32::try_from(INTERNED).unwrap().to_le_bytes());
    for _ in 0..INTERNED {
        data.push(b't');
        data.extend(0u32.to_le_bytes());
    }

    let object: Object = load(&data, PyVersion::PY312)
        .expect("a real module interns more strings than the test-mode limit allows");

    match object {
        Object::Tuple(items) => assert_eq!(items.len(), INTERNED),
        other => panic!("expected a tuple, got {other:?}"),
    }
}

#[test]
fn a_module_scale_object_count_still_traces_without_omissions() {
    const OBJECTS: usize = 300_000;
    let mut data: Vec<u8> = Vec::with_capacity(OBJECTS.saturating_add(5));
    data.push(b'(');
    data.extend(u32::try_from(OBJECTS).unwrap().to_le_bytes());
    data.extend(core::iter::repeat_n(b'N', OBJECTS));

    let (_, dump): (Object, RefTableDump) =
        load_with_reftable(&data, PyVersion::PY312).expect("a real module scale parses");

    assert_eq!(dump.entries.len(), OBJECTS.saturating_add(1));
    assert_eq!(dump.entries_omitted, 0);
    assert_eq!(dump.total_bytes, data.len());
}
