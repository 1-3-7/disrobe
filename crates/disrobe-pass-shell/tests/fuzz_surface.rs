#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_shell::batch::{arith, expand::MAX_EXPANSION_OUTPUT, payload};
use disrobe_pass_shell::pdf::{parse::Lexer as PdfLexer, xref};
use disrobe_pass_shell::{
    BashfuscatorLevel, BatchReport, DynamicPolicy, EmuState, Lexer, PdfReport, XlmRecovery,
    analyze_pdf, analyze_stomp, deobfuscate_batch, deobfuscate_vbs, deobfuscate_vbs_with_policy,
    detect, disassemble_pcode, disassemble_pcode_real, emulate, eval_if, expand_line,
    expand_repeated, extract_embedded, extract_from_bytes, format_identity, is_node_bash_obfuscate,
    is_pdf_document, is_xlm_macro_document, normalize_batch, obfuscator_detect, parse_ast,
    parse_bible, parse_for_f_string, parse_for_l, peel_indirection, peel_indirection_with_policy,
    recover_stages, recover_xlm, render_report, render_xlm_source, resolve_cfg, reverse_ast,
    reverse_bashfuscator, reverse_bashfuscator_auto, reverse_batch, reverse_chameleon,
    reverse_compress, reverse_encoding, reverse_invoke_stealth, reverse_isesteroids,
    reverse_launcher, reverse_node_bash_obfuscate, reverse_powerhell, reverse_psobf,
    reverse_string, reverse_token, semantic_lift, surface_iocs, tokenize_bash, unroll,
    vba_project_bin_from_bytes,
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

const MAX_INPUT_BYTES: usize = 8 * 1024;

fn ole_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0u8; 1024];
    bytes[0..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    bytes[24..26].copy_from_slice(&0x003eu16.to_le_bytes());
    bytes[26..28].copy_from_slice(&0x0003u16.to_le_bytes());
    bytes[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    bytes[30..32].copy_from_slice(&9u16.to_le_bytes());
    bytes[32..34].copy_from_slice(&6u16.to_le_bytes());
    bytes[44..48].copy_from_slice(&1u32.to_le_bytes());
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

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: PathBuf = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .map(PathBuf::from)
        .unwrap_or(manifest_dir);
    workspace_root.join("corpus").join("shell")
}

fn collect_fixtures() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![corpus_root()];
    while let Some(dir) = stack.pop() {
        let Ok(entries): Result<std::fs::ReadDir, std::io::Error> = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                let capped: Vec<u8> = if bytes.len() > MAX_INPUT_BYTES {
                    bytes[..MAX_INPUT_BYTES].to_vec()
                } else {
                    bytes
                };
                out.push(capped);
            }
        }
    }
    out
}

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    match rng.next_u64() % 7 {
        0 => {
            if !out.is_empty() {
                let idx: usize = rng.next_usize(out.len());
                out[idx] ^= 1u8 << rng.next_usize(8);
            }
        }
        1 => {
            let cut: usize = rng.next_usize(out.len() + 1);
            out.truncate(cut);
        }
        2 => {
            let count: usize = rng.next_usize(32) + 1;
            for _ in 0..count {
                if out.is_empty() {
                    break;
                }
                let idx: usize = rng.next_usize(out.len());
                out[idx] = rng.next_byte();
            }
        }
        3 => {
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 2 {
                    *b = 0xff;
                }
            }
        }
        4 => {
            let at: usize = rng.next_usize(out.len() + 1);
            let extra: usize = rng.next_usize(64);
            let chunk: Vec<u8> = (0..extra).map(|_| rng.next_byte()).collect();
            out.splice(at..at, chunk);
            out.truncate(MAX_INPUT_BYTES);
        }
        5 => {
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 3 {
                    *b = 0;
                }
            }
        }
        _ => {
            let len: usize = rng.next_usize(MAX_INPUT_BYTES);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    out
}

fn exercise_binary(bytes: &[u8]) {
    let _ = detect(bytes);
    let _ = parse_ast(bytes);
    let _ = tokenize_bash(bytes);
    let _ = Lexer::new(bytes).tokenize();
    let _ = disassemble_pcode(bytes);
    if let Ok(report) = disassemble_pcode_real(bytes) {
        for module in &report.modules {
            let _ = semantic_lift(module);
        }
    }
    let _ = analyze_stomp(bytes);
    let _ = extract_from_bytes(bytes);
    let _ = vba_project_bin_from_bytes(bytes);
    let recovery: Option<XlmRecovery> = recover_xlm(bytes);
    if let Some(recovery) = recovery {
        let _ = render_xlm_source(&recovery);
    }
    let _ = is_xlm_macro_document(bytes);
    let _ = is_pdf_document(bytes);
    let report: Option<PdfReport> = analyze_pdf(bytes);
    if let Some(report) = report {
        let _ = render_report(&report);
    }
    let mut object_parser: PdfLexer<'_> = PdfLexer::new(bytes);
    let _ = object_parser.parse_object(0);
    let mut indirect_parser: PdfLexer<'_> = PdfLexer::new(bytes);
    let _ = indirect_parser.parse_indirect_object();
    let _ = xref::load(bytes);
    exercise_chain(bytes);
}

fn exercise_text(text: &str) {
    let env: BTreeMap<String, String> = BTreeMap::new();
    let args: Vec<String> = vec!["a".to_owned(), "b".to_owned()];
    let state: EmuState = EmuState::default();

    let _ = deobfuscate_vbs(text);
    let _ = deobfuscate_vbs_with_policy(text, DynamicPolicy::default());
    let _ = format_identity(text);
    let _ = reverse_psobf(text);
    let _ = reverse_token(text);
    let _ = reverse_ast(text);
    let _ = reverse_string(text);
    let _ = reverse_encoding(text);
    let _ = reverse_compress(text);
    let _ = reverse_launcher(text);
    let _ = reverse_chameleon(text);
    let _ = reverse_isesteroids(text);
    let _ = reverse_invoke_stealth(text);
    let _ = reverse_powerhell(text);
    let _ = obfuscator_detect(text);
    let _ = parse_bible(text);

    let _ = deobfuscate_batch(text, &args);
    let _ = reverse_batch(text);
    let _ = resolve_cfg(text);
    let _ = normalize_batch(text);
    let _ = extract_embedded(text);
    let _ = surface_iocs(text, &[text]);
    let _ = eval_if(text);
    let _ = emulate(text, &env, &state);
    let _ = expand_line(text, &env, &args, true);
    let _ = expand_repeated(text, &env, &args, true, 16);
    let _ = arith::eval(text, &env);
    let _ = payload::reassemble_concat(text);
    let _ = payload::decode_utf16le(text.as_bytes());
    if let Some(loop_def) = parse_for_l(text) {
        let _ = unroll(&loop_def);
    }
    if let Some(loop_def) = parse_for_f_string(text, &env, &args, true) {
        let _ = unroll(&loop_def);
    }
    let _ = recover_stages(&env);

    let _ = reverse_bashfuscator_auto(text);
    let _ = reverse_bashfuscator(BashfuscatorLevel::Token, text);
    let _ = reverse_bashfuscator(BashfuscatorLevel::String, text);
    let _ = reverse_bashfuscator(BashfuscatorLevel::Obfuscate, text);
    let _ = reverse_bashfuscator(BashfuscatorLevel::Compress, text);
    let _ = is_node_bash_obfuscate(text);
    let _ = reverse_node_bash_obfuscate(text);
    let _ = peel_indirection(text);
    let _ = peel_indirection_with_policy(text, DynamicPolicy::default());
}

#[cfg(feature = "chain")]
fn exercise_chain(bytes: &[u8]) {
    use disrobe_core::chain::Pass;
    use disrobe_core::{Artifact, Rung};
    use disrobe_pass_shell::chain_detector::ShellPass;

    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let pass: ShellPass = ShellPass;
    let _ = pass.run(&artifact);
    let _ = pass.extract_children(&artifact);
}

#[cfg(not(feature = "chain"))]
const fn exercise_chain(_bytes: &[u8]) {}

fn run_one(bytes: &[u8]) {
    exercise_binary(bytes);
    if let Ok(text) = core::str::from_utf8(bytes) {
        exercise_text(text);
    }
}

#[test]
fn random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_4C17_F00D_BEEF);
    for _ in 0..6_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        run_one(&bytes);
    }
}

#[test]
fn ascii_biased_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_9099_C0DE_F00D);
    let alphabet: &[u8] = b"$(){}[]<>|&^~!#@*+-/%0123456789 \t\n\"'\\=,.:;_abcdefABCDEFxXForFn";
    for _ in 0..6_000 {
        let len: usize = rng.next_usize(512);
        let bytes: Vec<u8> = (0..len)
            .map(|_| alphabet[rng.next_usize(alphabet.len())])
            .collect();
        run_one(&bytes);
    }
}

#[test]
fn mutated_real_fixtures_never_panic() {
    let fixtures: Vec<Vec<u8>> = collect_fixtures();
    assert!(
        !fixtures.is_empty(),
        "no shell corpus fixtures found under {}",
        corpus_root().display()
    );
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_1234_ABCD_5678);
    for fixture in &fixtures {
        run_one(fixture);
        for _ in 0..200 {
            let mutated: Vec<u8> = mutate(fixture, &mut rng);
            run_one(&mutated);
        }
    }
}

#[test]
fn structured_malformed_inputs_never_panic() {
    let mut nested_pdf: Vec<u8> = b"%PDF-1.7\n1 0 obj\n".to_vec();
    for _ in 0..128 {
        nested_pdf.extend_from_slice(b"<< /A ");
    }
    nested_pdf.extend_from_slice(b"null");
    for _ in 0..128 {
        nested_pdf.extend_from_slice(b" >>");
    }

    let mut bash_depth: Vec<u8> = b"echo $(".to_vec();
    for _ in 0..512 {
        bash_depth.extend_from_slice(b"$(");
    }
    bash_depth.extend_from_slice(b"x");
    for _ in 0..512 {
        bash_depth.extend_from_slice(b")");
    }

    let seeds: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0xff, 0xfe, 0xfd, 0x00],
        ole_seed(),
        ooxml_seed(),
        nested_pdf,
        bash_depth,
        b"@echo off\n%random:~0,16777280%\nset X=%X%%X%\n%X%%X%%X%".to_vec(),
        b"powershell -EncodedCommand AAAAAAAAAAAAAAA=\n[IO.Compression.GZipStream]".to_vec(),
    ];
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_51A7_5AFE_1001);
    for seed in &seeds {
        run_one(seed);
        for _ in 0..64 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            run_one(&mutated);
        }
    }
}

#[test]
fn regression_unbalanced_arith_parens() {
    let cases: [&str; 4] = ["$(( )x)1)", "echo $(( a)b)c )", "$[ ]x]1]", "x$(()))y"];
    for case in cases {
        let _ = reverse_bashfuscator_auto(case);
        let _ = reverse_bashfuscator(BashfuscatorLevel::Token, case);
        let _ = reverse_bashfuscator(BashfuscatorLevel::Compress, case);
    }
}

#[test]
fn regression_reverse_batch_expansion_stays_bounded() {
    let refs: String = "%X%".repeat(100);
    let input: String = format!("set X=%X%%X%\n{refs}");
    let report: BatchReport = reverse_batch(&input);
    assert!(report.output.len() <= input.len() + MAX_EXPANSION_OUTPUT);
}

#[test]
fn regression_reverse_batch_rejects_oversized_random_width() {
    let input: &str = "@echo off\n%random:~0,16777280%";
    let report: BatchReport = reverse_batch(input);
    assert_eq!(report.output, input);
    assert_eq!(report.random_substitutions, 0);
}
