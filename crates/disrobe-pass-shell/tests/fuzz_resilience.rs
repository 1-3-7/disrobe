#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_shell::{
    Lexer, analyze_stomp, deobfuscate_vbs, detect, disassemble_pcode, disassemble_pcode_real,
    extract_from_bytes, parse_ast, reverse_psobf, tokenize_bash, vba_project_bin_from_bytes,
};

struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    const fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

fn ole_seed() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; 1024];
    v[0..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    v[24..26].copy_from_slice(&0x003eu16.to_le_bytes());
    v[26..28].copy_from_slice(&0x0003u16.to_le_bytes());
    v[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    v[30..32].copy_from_slice(&9u16.to_le_bytes());
    v[32..34].copy_from_slice(&6u16.to_le_bytes());
    v[44..48].copy_from_slice(&1u32.to_le_bytes());
    v
}

fn ooxml_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&[0u8; 26]);
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&[0u8; 18]);
    v
}

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    match rng.next_u64() % 5 {
        0 => {
            if !out.is_empty() {
                let idx: usize = rng.next_usize(out.len());
                out[idx] ^= 1u8 << rng.next_usize(8);
            }
        }
        1 => {
            if !out.is_empty() {
                let cut: usize = rng.next_usize(out.len());
                out.truncate(cut);
            }
        }
        2 => {
            let count: usize = rng.next_usize(out.len().max(1));
            for _ in 0..count {
                let idx: usize = rng.next_usize(out.len().max(1));
                if idx < out.len() {
                    out[idx] = rng.next_byte();
                }
            }
        }
        3 => {
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 2 {
                    *b = 0xff;
                }
            }
        }
        _ => {
            let len: usize = rng.next_usize(1024);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    out
}

fn exercise(bytes: &[u8]) {
    let _ = detect(bytes);
    let _ = parse_ast(bytes);
    let _ = disassemble_pcode(bytes);
    let _ = disassemble_pcode_real(bytes);
    let _ = analyze_stomp(bytes);
    let _ = extract_from_bytes(bytes);
    let _ = vba_project_bin_from_bytes(bytes);
    if let Ok(s) = core::str::from_utf8(bytes) {
        let _ = deobfuscate_vbs(s);
        let _ = reverse_psobf(s);
    }
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_4C17_0001_0002);
    for _ in 0..4_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn mutated_ole_and_ooxml_seeds_never_panic() {
    let seeds: [Vec<u8>; 3] = [ole_seed(), ooxml_seed(), Vec::new()];
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_9099_0304_0506);
    for seed in &seeds {
        for _ in 0..3_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
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
