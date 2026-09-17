#![allow(clippy::expect_used, clippy::panic)]
use std::collections::BTreeMap;
use std::time::Duration;

use disrobe_pass_pickle::{
    AnalysisOptions, Disassembly, PickleValue, Result, Session, VmTrace, analyze_all, analyze_deep,
    analyze_polyglot, analyze_safety, analyze_with_options, analyze_with_policy, disassemble,
    execute, execute_full, looks_like_pickle, needs_memo_table, reconstruct, render_disasm,
    to_python,
};
#[cfg(feature = "ml")]
use disrobe_pass_pickle::{detect_model, extract_ml};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 4096;
const CASES_PER_INPUT: usize = 2_304;
const BATCH_SIZE: usize = 2_304;
const CASE_BUDGET: Duration = Duration::from_millis(40);
const SUITE_BUDGET: Duration = Duration::from_mins(5);

const SATURATION_DOMAIN: u64 = 0x5049_434B_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 2] = [(u8::MAX, 2), (0, 3)];
const MAX_SCATTERED_OVERWRITES: usize = 32;

const NESTED_TUPLE_DEPTH: usize = 1024;
const PROTOCOL_TWO_SEVEN: &[u8] = b"\x80\x02K\x07.";
const ENTROPY_SPAN_SEED: u64 = 0x5049_434B_0001_0003;

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn deeply_nested_value_seed(depth: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0x80, 0x02, b'N'];
    bytes.extend(std::iter::repeat_n(0x85, depth));
    bytes.push(b'.');
    bytes
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("proto2-binint", PROTOCOL_TWO_SEVEN.to_vec()),
        CorpusEntry::new(
            "proto4-framed-short-string",
            b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01a\x94.".to_vec(),
        ),
        CorpusEntry::new("proto0-text-list", b"(lp0\nI1\naI2\na.".to_vec()),
        CorpusEntry::new(
            "proto5-empty-dict",
            b"\x80\x05\x95\x00\x00\x00\x00\x00\x00\x00\x00}\x94.".to_vec(),
        ),
        CorpusEntry::new("proto1-binput-list", b"]q\x00(K\x01K\x02K\x03e.".to_vec()),
        CorpusEntry::new(
            "proto3-builtins-exec-reduce",
            b"\x80\x03cbuiltins\nexec\nq\x00X\x04\x00\x00\x00pass\x85\x86.".to_vec(),
        ),
        CorpusEntry::new(
            "proto2-short-binstring-dict",
            b"\x80\x02}q\x00(U\x01aq\x01K\x01u.".to_vec(),
        ),
        CorpusEntry::new("proto0-global-newobj", b"c__main__\nfoo\n(t\x81.".to_vec()),
        CorpusEntry::new(
            "proto4-framed-builtins-unicode",
            b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94.".to_vec(),
        ),
        CorpusEntry::new(
            "deeply-nested-tuples",
            deeply_nested_value_seed(NESTED_TUPLE_DEPTH),
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

fn probe(bytes: &[u8]) {
    consume(looks_like_pickle(bytes));
    consume(analyze_polyglot(bytes));
    #[cfg(feature = "ml")]
    {
        consume(detect_model(bytes));
        consume(extract_ml(bytes));
    }
    consume(analyze_all(bytes));

    let disassembly: Result<Disassembly> = disassemble(bytes);
    if let Ok(disassembly) = disassembly {
        consume(render_disasm(&disassembly));

        let trace: Result<VmTrace> = execute(&disassembly);
        if let Ok(trace) = trace {
            let options: AnalysisOptions = AnalysisOptions::default();
            consume(to_python(&trace.result));
            consume(analyze_safety(&trace));
            consume(analyze_deep(&trace));
            consume(analyze_with_options(&trace, &options));
            consume(analyze_with_policy(&trace, &options.policy));
            consume(needs_memo_table(&trace.result));
        }

        let full: Result<(VmTrace, BTreeMap<u64, PickleValue>)> = execute_full(&disassembly);
        if let Ok((trace, memo)) = full {
            consume(reconstruct(&trace.result, &memo, trace.root_memo_key));
        }

        let mut session: Session = Session::new();
        consume(session.run(&disassembly));
    }
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
fn deep_nesting_does_not_overflow_the_disassembler_or_the_machine() {
    for depth in [64usize, 255, 256, 257, 1_024, 4_096, 16_384] {
        let seed: Vec<u8> = deeply_nested_value_seed(depth);
        consume(looks_like_pickle(&seed));
        if let Ok(disassembly) = disassemble(&seed) {
            consume(execute(&disassembly));
        }
    }
}

#[test]
fn the_protocol_two_seed_disassembles_and_executes_to_the_integer_it_encodes() {
    assert!(looks_like_pickle(PROTOCOL_TWO_SEVEN));
    let disassembly: Disassembly = disassemble(PROTOCOL_TWO_SEVEN)
        .expect("the constructed protocol 2 pickle must disassemble, or every case is inert");
    let trace: VmTrace = execute(&disassembly).expect("the constructed pickle must execute");
    assert_eq!(trace.protocol, 2);
    assert_eq!(trace.result, PickleValue::Int(7));
}
