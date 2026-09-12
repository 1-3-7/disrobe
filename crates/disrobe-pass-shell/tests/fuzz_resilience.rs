#![allow(clippy::expect_used, clippy::panic)]
use std::time::Duration;

use disrobe_pass_shell::{
    Lexer, analyze_stomp, deobfuscate_vbs, detect, disassemble_pcode, disassemble_pcode_real,
    extract_from_bytes, parse_ast, reverse_psobf, tokenize_bash, vba_project_bin_from_bytes,
};
use disrobe_testkit::{CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 1024;
const CASES_PER_INPUT: usize = 4_096;
const BATCH_SIZE: usize = 4_096;
const CASE_BUDGET: Duration = Duration::from_millis(30);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const SATURATION_DOMAIN: u64 = 0x5348_4C17_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 1] = [(u8::MAX, 2)];

const ENTROPY_SPAN_SEED: u64 = 0x5348_4C17_0001_0003;

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn ole_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    bytes.resize(24, 0);
    bytes.extend_from_slice(&0x003eu16.to_le_bytes());
    bytes.extend_from_slice(&0x0003u16.to_le_bytes());
    bytes.extend_from_slice(&0xfffeu16.to_le_bytes());
    bytes.extend_from_slice(&9u16.to_le_bytes());
    bytes.extend_from_slice(&6u16.to_le_bytes());
    bytes.resize(44, 0);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.resize(1024, 0);
    bytes
}

fn ooxml_seed() -> Vec<u8> {
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
        CorpusEntry::new("ole-compound-file", ole_seed()),
        CorpusEntry::new("ooxml-zip-shell", ooxml_seed()),
        CorpusEntry::new("random-span", vec![0u8; RANDOM_SPAN_BYTES]),
        CorpusEntry::new("entropy-span", entropy_span(RANDOM_SPAN_BYTES)),
    ]
}

fn saturate(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ SATURATION_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    let pick: usize = rng.below_usize(SATURATION_PATTERNS.len().saturating_add(1));
    let Some(&(value, sparsity)): Option<&(u8, u32)> = SATURATION_PATTERNS.get(pick) else {
        let changes: usize = rng.below_usize(out.len().saturating_add(1));
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

fn probe(bytes: &[u8]) {
    let _ = detect(bytes);
    let _ = parse_ast(bytes);
    let _ = disassemble_pcode(bytes);
    let _ = disassemble_pcode_real(bytes);
    let _ = analyze_stomp(bytes);
    let _ = extract_from_bytes(bytes);
    let _ = vba_project_bin_from_bytes(bytes);
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
    let _ = deobfuscate_vbs(&text);
    let _ = reverse_psobf(&text);
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
fn the_constructed_ooxml_seed_reads_as_a_zip_container_carrying_no_vba_project() {
    let outcome: disrobe_pass_shell::Result<Vec<u8>> = vba_project_bin_from_bytes(&ooxml_seed());
    match outcome {
        Err(disrobe_pass_shell::Error::VbaPcode { reason }) => {
            assert!(reason.contains("no vbaProject.bin"), "{reason}");
        }
        other => panic!(
            "the constructed zip must be walked as a container, or every ooxml case is inert: {other:?}"
        ),
    }
}

#[test]
fn lexers_cap_repeated_tokens_and_token_text() {
    const TOKEN_CAP: usize = 65_536;
    const TOKEN_TEXT_CAP: usize = 65_536;
    const TOTAL_TOKEN_TEXT_CAP: usize = 8 * 1024 * 1024;
    const LEXER_INPUT_CAP: usize = 8 * 1024 * 1024;
    const SUBSTITUTION_DEPTH_CAP: usize = 256;
    const CHUNK_SOURCE_BYTES: usize = 21_000usize;
    const CHUNK_COUNT: usize = 134usize;
    let input: Vec<u8> = vec![b'('; TOKEN_CAP + 2usize];
    let bash_tokens: Vec<disrobe_pass_shell::BashToken> = tokenize_bash(&input);
    let powershell_tokens: Vec<disrobe_pass_shell::Token> = Lexer::new(&input).tokenize();
    let long_input: Vec<u8> = vec![b'a'; TOKEN_TEXT_CAP + 2usize];
    let long_bash_tokens: Vec<disrobe_pass_shell::BashToken> = tokenize_bash(&long_input);
    let long_powershell_tokens: Vec<disrobe_pass_shell::Token> = Lexer::new(&long_input).tokenize();
    let mut exact_invalid_token: Vec<u8> = Vec::with_capacity(TOKEN_TEXT_CAP);
    exact_invalid_token.push(b'\"');
    exact_invalid_token.extend(std::iter::repeat_n(0xffu8, TOKEN_TEXT_CAP - 1usize));
    let exact_invalid_bash_tokens: Vec<disrobe_pass_shell::BashToken> =
        tokenize_bash(&exact_invalid_token);
    let exact_invalid_powershell_tokens: Vec<disrobe_pass_shell::Token> =
        Lexer::new(&exact_invalid_token).tokenize();
    let input_cap_plus_one: Vec<u8> = vec![b'a'; LEXER_INPUT_CAP + 1usize];
    let bounded_bash_tokens: Vec<disrobe_pass_shell::BashToken> =
        tokenize_bash(&input_cap_plus_one);
    let bounded_powershell_tokens: Vec<disrobe_pass_shell::Token> =
        Lexer::new(&input_cap_plus_one).tokenize();
    let nested_at_depth_cap: Vec<u8> = b"$(".repeat(SUBSTITUTION_DEPTH_CAP);
    let nested_above_depth_cap: Vec<u8> = b"$(".repeat(SUBSTITUTION_DEPTH_CAP + 1usize);
    let nested_at_depth_tokens: Vec<disrobe_pass_shell::BashToken> =
        tokenize_bash(&nested_at_depth_cap);
    let nested_above_depth_tokens: Vec<disrobe_pass_shell::BashToken> =
        tokenize_bash(&nested_above_depth_cap);
    let mut aggregate_input: Vec<u8> =
        Vec::with_capacity(CHUNK_COUNT.saturating_mul(CHUNK_SOURCE_BYTES.saturating_add(1usize)));
    let mut chunk: usize = 0usize;
    while chunk < CHUNK_COUNT {
        aggregate_input.extend(std::iter::repeat_n(b'a', CHUNK_SOURCE_BYTES));
        aggregate_input.push(b'(');
        chunk = chunk.saturating_add(1usize);
    }
    let aggregate_bash_tokens: Vec<disrobe_pass_shell::BashToken> = tokenize_bash(&aggregate_input);
    let aggregate_powershell_tokens: Vec<disrobe_pass_shell::Token> =
        Lexer::new(&aggregate_input).tokenize();
    let mut invalid_aggregate_input: Vec<u8> =
        Vec::with_capacity(CHUNK_COUNT.saturating_mul(CHUNK_SOURCE_BYTES.saturating_add(3usize)));
    let mut invalid_chunk: usize = 0usize;
    while invalid_chunk < CHUNK_COUNT {
        invalid_aggregate_input.push(b'\"');
        invalid_aggregate_input.extend(std::iter::repeat_n(0xffu8, CHUNK_SOURCE_BYTES));
        invalid_aggregate_input.push(b'\"');
        invalid_aggregate_input.push(b'(');
        invalid_chunk = invalid_chunk.saturating_add(1usize);
    }
    let invalid_aggregate_bash_tokens: Vec<disrobe_pass_shell::BashToken> =
        tokenize_bash(&invalid_aggregate_input);
    let invalid_aggregate_powershell_tokens: Vec<disrobe_pass_shell::Token> =
        Lexer::new(&invalid_aggregate_input).tokenize();
    let bash_text_bytes: usize = aggregate_bash_tokens
        .iter()
        .map(|token: &disrobe_pass_shell::BashToken| token.text.len())
        .sum();
    let powershell_text_bytes: usize = aggregate_powershell_tokens
        .iter()
        .map(|token: &disrobe_pass_shell::Token| token.text.len())
        .sum();
    let invalid_bash_text_capacity: usize = invalid_aggregate_bash_tokens
        .iter()
        .map(|token: &disrobe_pass_shell::BashToken| token.text.capacity())
        .sum();
    let invalid_powershell_text_capacity: usize = invalid_aggregate_powershell_tokens
        .iter()
        .map(|token: &disrobe_pass_shell::Token| token.text.capacity())
        .sum();

    assert!(bash_tokens.len() <= TOKEN_CAP + 2usize);
    assert!(powershell_tokens.len() <= TOKEN_CAP + 2usize);
    assert!(long_bash_tokens[0].text.len() <= TOKEN_TEXT_CAP);
    assert!(long_powershell_tokens[0].text.len() <= TOKEN_TEXT_CAP);
    assert!(exact_invalid_bash_tokens[0].text.len() <= TOKEN_TEXT_CAP);
    assert!(exact_invalid_powershell_tokens[0].text.len() <= TOKEN_TEXT_CAP);
    assert!(
        bounded_bash_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::BashToken| {
                token.kind == disrobe_pass_shell::BashTokenKind::Truncated
                    && token.start == LEXER_INPUT_CAP
                    && token.end == LEXER_INPUT_CAP + 1usize
            })
    );
    assert!(
        bounded_powershell_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::Token| {
                token.kind == disrobe_pass_shell::TokenKind::Truncated
                    && token.start == LEXER_INPUT_CAP
                    && token.end == LEXER_INPUT_CAP + 1usize
            })
    );
    assert!(
        !nested_at_depth_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::BashToken| {
                token.kind == disrobe_pass_shell::BashTokenKind::Truncated
            })
    );
    assert!(
        nested_above_depth_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::BashToken| {
                token.kind == disrobe_pass_shell::BashTokenKind::Truncated
            })
    );
    assert!(bash_text_bytes <= TOTAL_TOKEN_TEXT_CAP);
    assert!(powershell_text_bytes <= TOTAL_TOKEN_TEXT_CAP);
    assert!(invalid_aggregate_bash_tokens.len() > 100usize);
    assert!(invalid_aggregate_powershell_tokens.len() > 100usize);
    assert!(
        invalid_bash_text_capacity <= TOTAL_TOKEN_TEXT_CAP,
        "{invalid_bash_text_capacity}"
    );
    assert!(
        invalid_powershell_text_capacity <= TOTAL_TOKEN_TEXT_CAP,
        "{invalid_powershell_text_capacity}"
    );
    assert!(
        bash_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::BashToken| {
                token.kind == disrobe_pass_shell::BashTokenKind::Truncated
            })
    );
    assert!(
        powershell_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::Token| {
                token.kind == disrobe_pass_shell::TokenKind::Truncated
            })
    );
    assert!(
        long_bash_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::BashToken| {
                token.kind == disrobe_pass_shell::BashTokenKind::Truncated
            })
    );
    assert!(
        long_powershell_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::Token| {
                token.kind == disrobe_pass_shell::TokenKind::Truncated
            })
    );
    assert!(
        exact_invalid_bash_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::BashToken| {
                token.kind == disrobe_pass_shell::BashTokenKind::Truncated
            })
    );
    assert!(
        exact_invalid_powershell_tokens
            .iter()
            .any(|token: &disrobe_pass_shell::Token| {
                token.kind == disrobe_pass_shell::TokenKind::Truncated
            })
    );
}
