#![allow(clippy::expect_used, clippy::panic)]
use std::time::Duration;

use disrobe_pass_beam::chunks::{self, LineChunk, LiteralChunk, StringTable};
use disrobe_pass_beam::{
    AtomTable, BeamFile, CodeChunk, DebugInfo, EzArchive, EzQuota, ModuleDocs, RawBeam, Result,
    Term, decode_etf, disassemble, lift, parse_dbgi, parse_docs, recover_elixir,
    recover_elixir_with_docs, recover_erlang, symbolic_disassemble,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 4096;
const CASES_PER_INPUT: usize = 4_096;
const BATCH_SIZE: usize = 4_096;
const CASE_BUDGET: Duration = Duration::from_millis(40);
const SUITE_BUDGET: Duration = Duration::from_mins(5);

const SATURATION_DOMAIN: u64 = 0x4245_414D_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 2] = [(u8::MAX, 2), (0, 3)];
const MAX_SCATTERED_OVERWRITES: usize = 32;

const SEED_MODULE_NAME: &str = "mod";
const NESTED_TUPLE_DEPTH: usize = 512;
const OPCODE_MAX: u32 = 200;
const FUZZ_MODULE: &str = "Fuzz.Module";
const ENTROPY_SPAN_SEED: u64 = 0x4245_414D_0001_0003;

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn beam_seed() -> Vec<u8> {
    let mut chunks_blob: Vec<u8> = Vec::new();
    chunks_blob.extend_from_slice(b"AtU8");
    chunks_blob.extend_from_slice(&8u32.to_be_bytes());
    chunks_blob.extend_from_slice(&1u32.to_be_bytes());
    chunks_blob.push(3);
    chunks_blob.extend_from_slice(SEED_MODULE_NAME.as_bytes());
    let form_len: u32 = u32::try_from(chunks_blob.len().saturating_add(4))
        .expect("the constructed form is a few dozen bytes long");
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"FOR1");
    bytes.extend_from_slice(&form_len.to_be_bytes());
    bytes.extend_from_slice(b"BEAM");
    bytes.extend_from_slice(&chunks_blob);
    bytes
}

fn beam_chunk_boundary_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"FOR1");
    bytes.extend_from_slice(&8u32.to_be_bytes());
    bytes.extend_from_slice(b"BEAM");
    bytes.extend_from_slice(b"At");
    bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    bytes
}

fn etf_seed() -> Vec<u8> {
    vec![131, 104, 2, 97, 1, 97, 2]
}

fn deeply_nested_etf_seed(depth: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![131];
    for _ in 0..depth {
        bytes.extend_from_slice(&[104, 1]);
    }
    bytes.push(106);
    bytes
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("beam-atom-chunk", beam_seed()),
        CorpusEntry::new("beam-chunk-boundary", beam_chunk_boundary_seed()),
        CorpusEntry::new("etf-small-tuple", etf_seed()),
        CorpusEntry::new(
            "etf-deeply-nested",
            deeply_nested_etf_seed(NESTED_TUPLE_DEPTH),
        ),
        CorpusEntry::new(
            "compact-term-run",
            vec![1, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8],
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

fn probe_term(term: &Term) {
    consume(parse_docs(term));
    let debug_info: Result<DebugInfo> = parse_dbgi(term);
    if let Ok(debug_info) = debug_info {
        consume(recover_elixir(FUZZ_MODULE, &debug_info));
        let docs: Option<ModuleDocs> = parse_docs(term);
        consume(recover_elixir_with_docs(
            FUZZ_MODULE,
            &debug_info,
            docs.as_ref(),
        ));
    }
}

fn probe(bytes: &[u8]) {
    consume(AtomTable::parse_utf8(bytes));
    consume(AtomTable::parse_latin1(bytes));
    consume(AtomTable::parse_utf8_any(bytes));
    consume(CodeChunk::parse(bytes));
    consume(StringTable::parse(bytes));
    consume(chunks::parse_export_table(bytes));
    consume(chunks::parse_import_table(bytes));
    consume(chunks::parse_local_table(bytes));
    consume(chunks::parse_fun_table(bytes));
    consume(LiteralChunk::parse(bytes));
    consume(LineChunk::parse(bytes));
    consume(EzArchive::parse(bytes));
    consume(EzArchive::parse_with_quota(bytes, EzQuota::default()));

    let code: CodeChunk = CodeChunk {
        sub_size: 0,
        instruction_set: 0,
        opcode_max: OPCODE_MAX,
        num_labels: 0,
        num_functions: 0,
        code: bytes.to_vec(),
    };
    consume(disassemble(&code));

    if let Ok(term) = decode_etf(bytes) {
        probe_term(&term);
    }

    if let Ok(raw) = RawBeam::parse(bytes) {
        consume(BeamFile::from_raw(&raw));
    }

    if let Ok(beam) = BeamFile::parse(bytes) {
        consume(lift(&beam));
        consume(recover_erlang(&beam));
        consume(symbolic_disassemble(&beam));
        if let Some(dbgi) = &beam.chunks.dbgi {
            probe_term(&dbgi.term);
        }
        if let Some(docs) = &beam.chunks.docs {
            probe_term(&docs.term);
        }
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
fn deep_nesting_does_not_overflow_the_external_term_decoder() {
    for depth in [64usize, 255, 256, 257, 512, 4_096, 16_384] {
        let seed: Vec<u8> = deeply_nested_etf_seed(depth);
        if let Ok(term) = decode_etf(&seed) {
            consume(parse_dbgi(&term));
            consume(parse_docs(&term));
        }
    }
}

#[test]
fn the_constructed_seeds_parse_as_the_formats_they_stand_for() {
    let raw: RawBeam = RawBeam::parse(&beam_seed())
        .expect("the constructed beam form must parse, or every beam case is inert");
    assert_eq!(raw.raw_chunks.len(), 1);

    let atoms: AtomTable = AtomTable::parse_utf8(
        raw.raw_chunks
            .first()
            .expect("a one-chunk form yields a first chunk")
            .data
            .as_slice(),
    )
    .expect("the constructed atom chunk must parse");
    assert_eq!(atoms.atoms, vec![SEED_MODULE_NAME.to_owned()]);

    let term: Term = decode_etf(&etf_seed())
        .expect("the constructed external term must decode, or every etf case is inert");
    assert_eq!(
        term,
        Term::Tuple(vec![Term::SmallInt(1), Term::SmallInt(2)])
    );
}
