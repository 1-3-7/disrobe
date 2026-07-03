#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

use disrobe_pass_sourcedefender::{
    DerivedKey, InlinedExtractOptions, ModernGcmFraming, SourceRecoverOpts, ascii85_decode,
    base85_decode_rfc1924, basename_of, classify_container, decode_armored_line,
    decrypt_modern_gcm_with_key, decrypt_pye, decrypt_pye_to_source, decrypt_pye_with_key,
    derive_aes_key, extract_inlined, frame_modern_gcm_body, hex_decode, hex_encode,
    locate_inlined_blocks, parse_array_envelope, parse_msgpack_envelope, parse_pye_frame,
    python_decoded_header, recover_from_marshal_bytes, recover_from_plaintext, recover_layered,
    recover_layered_with_modern_key, render_decoded_with_header, strip_extension,
    strip_sourcedefender_decorators,
};

const LEGACY_HELLO: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");
const MODERN_TRIAL: &[u8] =
    include_bytes!("../../../corpus/python/sourcedefender/known_v16_trial.pye");
const MODERN_KNOWN_KEY: &[u8] =
    include_bytes!("../../../corpus/python/sourcedefender/crafted_modern_aesgcm_known_key.pye");

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

fn silence_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {}));
    });
}

const MAX_FUZZ_INPUT: usize = 4096;

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    if out.len() > MAX_FUZZ_INPUT {
        out.truncate(MAX_FUZZ_INPUT);
    }
    match rng.next_u64() % 8 {
        0 => {
            if !out.is_empty() {
                let idx: usize = rng.next_usize(out.len());
                if let Some(b) = out.get_mut(idx) {
                    *b ^= 1u8 << rng.next_usize(8);
                }
            }
        }
        1 => {
            let cut: usize = rng.next_usize(out.len().saturating_add(1));
            out.truncate(cut);
        }
        2 => {
            let count: usize = rng.next_usize(out.len().max(1));
            for _ in 0..count {
                let idx: usize = rng.next_usize(out.len().max(1));
                if let Some(b) = out.get_mut(idx) {
                    *b = rng.next_byte();
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
        4 => {
            let extra: usize = rng.next_usize(MAX_FUZZ_INPUT.saturating_sub(out.len()).max(1));
            for _ in 0..extra {
                out.push(rng.next_byte());
            }
        }
        5 => {
            let at: usize = rng.next_usize(out.len().saturating_add(1));
            let chunk: usize = rng.next_usize(64).max(1);
            let filler: Vec<u8> = (0..chunk).map(|_| rng.next_byte()).collect();
            let at: usize = at.min(out.len());
            out.splice(at..at, filler);
            if out.len() > MAX_FUZZ_INPUT {
                out.truncate(MAX_FUZZ_INPUT);
            }
        }
        6 => {
            let len: usize = rng.next_usize(MAX_FUZZ_INPUT);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
        _ => {
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 3 {
                    *b = b'\n';
                }
            }
        }
    }
    out
}

fn exercise_all(bytes: &[u8], rng: &mut Xorshift64) {
    let _ = base85_decode_rfc1924(bytes);
    let _ = ascii85_decode(bytes);
    let _ = decode_armored_line(bytes);
    let _ = hex_decode(bytes);
    let _ = hex_encode(bytes);
    let _ = parse_msgpack_envelope(bytes);
    let _ = parse_array_envelope(bytes);
    let _ = classify_container(bytes);
    let _ = decrypt_pye(bytes, "fuzz.pye");
    let _ = decrypt_pye(bytes, "");
    let _ = recover_layered(bytes, "fuzz.pye");
    let _ = decrypt_pye_to_source(bytes, "fuzz.pye", SourceRecoverOpts::default());
    let _ = recover_from_plaintext(bytes, None, SourceRecoverOpts::default());
    let _ = recover_from_marshal_bytes(bytes, None, None, SourceRecoverOpts::default());

    let mut key_bytes: [u8; 32] = [0u8; 32];
    for slot in &mut key_bytes {
        *slot = rng.next_byte();
    }
    let derived: DerivedKey = DerivedKey(key_bytes);
    let _ = decrypt_pye_with_key(bytes, "fuzz.pye", &derived);
    let _ = recover_layered_with_modern_key(bytes, "fuzz.pye", &key_bytes);

    let framing: ModernGcmFraming = frame_modern_gcm_body(bytes);
    let _ = decrypt_modern_gcm_with_key(&framing, bytes, &key_bytes);
    let shorter: &[u8] = bytes.get(..bytes.len() / 2).unwrap_or(bytes);
    let _ = decrypt_modern_gcm_with_key(&framing, shorter, &key_bytes);

    if let Ok(text) = core::str::from_utf8(bytes) {
        let _ = parse_pye_frame(text);
        let _ = locate_inlined_blocks(text);
        let _ = extract_inlined(text, "fuzz.py", InlinedExtractOptions::default());
        let _ = extract_inlined(
            text,
            "fuzz.py",
            InlinedExtractOptions {
                require_known_basename: true,
            },
        );
        let _ = strip_sourcedefender_decorators(text);
        let _ = basename_of(text);
        let _ = strip_extension(text);
        let _ = derive_aes_key(text);
        let _ = render_decoded_with_header(text, std::time::Duration::from_millis(1), "3.14");
        let _ = python_decoded_header(std::time::Duration::from_millis(1), "3.14");
    }
}

fn run_fuzz(seeds: &[&[u8]], seed: u64, iterations: usize) {
    silence_panic_hook();
    let mut rng: Xorshift64 = Xorshift64::new(seed);
    for _ in 0..iterations {
        let which: usize = rng.next_usize(seeds.len().max(1));
        let base: &[u8] = seeds.get(which).copied().unwrap_or(b"");
        let mutated: Vec<u8> = mutate(base, &mut rng);
        let mut inner_rng: Xorshift64 = Xorshift64::new(rng.next_u64());
        let outcome: Result<(), Box<dyn std::any::Any + Send>> =
            catch_unwind(AssertUnwindSafe(|| {
                exercise_all(&mutated, &mut inner_rng);
            }));
        if outcome.is_err() {
            let _ = std::panic::take_hook();
            panic!(
                "sourcedefender fuzz panicked on a {}-byte input derived from seed index {which}",
                mutated.len()
            );
        }
    }
}

#[test]
fn mutated_real_fixtures_never_panic() {
    let seeds: [&[u8]; 4] = [LEGACY_HELLO, MODERN_TRIAL, MODERN_KNOWN_KEY, b""];
    run_fuzz(&seeds, 0x50DE_FE0D_F1B7_0001, 30_000);
}

#[test]
fn pure_random_inputs_never_panic() {
    silence_panic_hook();
    let mut rng: Xorshift64 = Xorshift64::new(0x50DE_FE0D_2222_0001);
    for _ in 0..20_000 {
        let len: usize = rng.next_usize(MAX_FUZZ_INPUT);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let mut inner: Xorshift64 = Xorshift64::new(rng.next_u64());
        let outcome: Result<(), Box<dyn std::any::Any + Send>> =
            catch_unwind(AssertUnwindSafe(|| {
                exercise_all(&bytes, &mut inner);
            }));
        if outcome.is_err() {
            let _ = std::panic::take_hook();
            panic!("sourcedefender fuzz panicked on a {len}-byte random input");
        }
    }
}

#[test]
fn structured_armor_mutations_never_panic() {
    let mut seed: Vec<u8> = Vec::new();
    seed.extend_from_slice(b"--BEGIN SOURCEDEFENDER FILE---\n");
    seed.extend_from_slice(b"GhOt7h7Jm.?sE?I;!%a(cCM6@0X(^n\n");
    seed.extend_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    seed.extend_from_slice(b"---END SOURCEDEFENDER FILE----\n");
    let mut modern: Vec<u8> = Vec::new();
    modern.extend_from_slice(b"--BEGIN PYE FILE---\n");
    modern.extend_from_slice(b"D3F3D1B2730BC6A0DD834EAFE412B908\n");
    modern.extend_from_slice(b"---END PYE FILE----\n");
    let seeds: [&[u8]; 2] = [seed.as_slice(), modern.as_slice()];
    run_fuzz(&seeds, 0x50DE_FE0D_3333_0001, 20_000);
}
