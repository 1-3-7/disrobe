#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Once;

use disrobe_pass_shell::{
    BashfuscatorLevel, DynamicPolicy, EmuState, Lexer, analyze_stomp, deobfuscate_batch,
    deobfuscate_vbs, detect, disassemble_pcode, disassemble_pcode_real, emulate, eval_if,
    expand_line, extract_embedded, extract_from_bytes, is_node_bash_obfuscate,
    is_xlm_macro_document, normalize_batch, obfuscator_detect, parse_ast, parse_bible,
    parse_for_f_string, parse_for_l, peel_indirection, peel_indirection_with_policy,
    recover_stages, recover_xlm, resolve_cfg, reverse_ast, reverse_bashfuscator,
    reverse_bashfuscator_auto, reverse_batch, reverse_chameleon, reverse_compress,
    reverse_encoding, reverse_invoke_stealth, reverse_isesteroids, reverse_launcher,
    reverse_node_bash_obfuscate, reverse_powerhell, reverse_psobf, reverse_string, reverse_token,
    semantic_lift, surface_iocs, tokenize_bash, unroll, vba_project_bin_from_bytes,
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

fn silence_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        panic::set_hook(Box::new(|_info: &panic::PanicHookInfo<'_>| {}));
    });
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
    let _ = recover_xlm(bytes);
    let _ = is_xlm_macro_document(bytes);
}

fn exercise_text(text: &str) {
    let env: BTreeMap<String, String> = BTreeMap::new();
    let args: Vec<String> = vec!["a".to_owned(), "b".to_owned()];
    let state: EmuState = EmuState::default();

    let _ = deobfuscate_vbs(text);
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

fn run_one(bytes: &[u8]) -> Result<(), String> {
    let result: Result<(), Box<dyn std::any::Any + Send>> =
        panic::catch_unwind(AssertUnwindSafe(|| {
            exercise_binary(bytes);
            if let Ok(text) = core::str::from_utf8(bytes) {
                exercise_text(text);
            }
        }));
    result.map_err(|payload: Box<dyn std::any::Any + Send>| {
        let msg: &str = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        let mut hex: String = String::with_capacity(192);
        for byte in bytes.iter().copied().take(96) {
            push_hex_byte(&mut hex, byte);
        }
        format!(
            "panic on input ({} bytes): {msg}\n  hex: {hex}",
            bytes.len()
        )
    })
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
    out.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
}

#[test]
fn random_inputs_never_panic() {
    silence_panics();
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_4C17_F00D_BEEF);
    let mut failures: Vec<String> = Vec::new();
    for _ in 0..6_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        if let Err(report) = run_one(&bytes) {
            failures.push(report);
            if failures.len() >= 8 {
                break;
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn ascii_biased_inputs_never_panic() {
    silence_panics();
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_9099_C0DE_F00D);
    let alphabet: &[u8] = b"$(){}[]<>|&^~!#@*+-/%0123456789 \t\n\"'\\=,.:;_abcdefABCDEFxXForFn";
    let mut failures: Vec<String> = Vec::new();
    for _ in 0..6_000 {
        let len: usize = rng.next_usize(512);
        let bytes: Vec<u8> = (0..len)
            .map(|_| alphabet[rng.next_usize(alphabet.len())])
            .collect();
        if let Err(report) = run_one(&bytes) {
            failures.push(report);
            if failures.len() >= 8 {
                break;
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn mutated_real_fixtures_never_panic() {
    silence_panics();
    let fixtures: Vec<Vec<u8>> = collect_fixtures();
    assert!(
        !fixtures.is_empty(),
        "no shell corpus fixtures found under {}",
        corpus_root().display()
    );
    let mut rng: Xorshift64 = Xorshift64::new(0x5348_1234_ABCD_5678);
    let mut failures: Vec<String> = Vec::new();
    for fixture in &fixtures {
        if run_one(fixture).is_err() {
            failures.push(format!("clean fixture panicked ({} bytes)", fixture.len()));
        }
        for _ in 0..200 {
            let mutated: Vec<u8> = mutate(fixture, &mut rng);
            if let Err(report) = run_one(&mutated) {
                failures.push(report);
                if failures.len() >= 8 {
                    break;
                }
            }
        }
        if failures.len() >= 8 {
            break;
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
