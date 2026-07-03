#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_swift_objc::{
    analyze, decode_entitlements_from_code_signature, decode_entitlements_xml, extract_ipa,
    ipa_inventory, looks_like_swift_mangled, parse_info_plist, parse_slice, parse_swiftinterface,
    swift_demangle, walk_fat,
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

fn macho64_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    v.extend_from_slice(&0x0100_0007u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&72u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    while v.len() < 256 {
        v.push(0);
    }
    v
}

fn fat_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
    v.extend_from_slice(&2u32.to_be_bytes());
    while v.len() < 128 {
        v.push(0);
    }
    v
}

fn zip_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&[0u8; 26]);
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&[0u8; 18]);
    v
}

fn fuzz_str(rng: &mut Xorshift64) -> String {
    let len: usize = rng.next_usize(96);
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    let alphabet: &[u8] = b"$_TtSsViMNCPfgyz0123456789AaBbZ\xc3\xa9\xf0\x9f\x98\x80";
    for _ in 0..len {
        if rng.next_u64().trailing_zeros() >= 2 {
            bytes.push(rng.next_byte());
        } else {
            bytes.push(alphabet[rng.next_usize(alphabet.len())]);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    let kind: u64 = rng.next_u64() % 6;
    match kind {
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
        4 => {
            let count: usize = rng.next_usize(16);
            for _ in 0..count {
                let idx: usize = rng.next_usize(out.len().max(1));
                if idx + 4 <= out.len() {
                    out[idx..idx + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
                }
            }
        }
        _ => {
            let len: usize = rng.next_usize(512);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    out
}

fn exercise_bytes(bytes: &[u8]) {
    let _ = analyze(bytes);
    let _ = walk_fat(bytes);
    if let Ok(parsed) = parse_slice(bytes) {
        let _ = disrobe_pass_swift_objc::symbol_names(bytes, &parsed);
    }
    let _ = extract_ipa(bytes);
    let _ = ipa_inventory(bytes);
    let _ = parse_info_plist(bytes);
    let _ = decode_entitlements_from_code_signature(bytes);
    let _ = decode_entitlements_xml(bytes);
    if let Ok(s) = core::str::from_utf8(bytes) {
        let _ = parse_swiftinterface(s);
    }
}

fn exercise_str(s: &str) {
    let _ = swift_demangle(s);
    let _ = looks_like_swift_mangled(s);
}

#[test]
fn pure_random_bytes_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x5717_0B7C_5717_0001);
    for _ in 0..4_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise_bytes(&bytes);
    }
}

#[test]
fn mutated_macho_seeds_never_panic() {
    let seeds: [Vec<u8>; 4] = [macho64_seed(), fat_seed(), zip_seed(), Vec::new()];
    let mut rng: Xorshift64 = Xorshift64::new(0x5717_0102_0304_0506);
    for seed in &seeds {
        for _ in 0..3_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise_bytes(&mutated);
        }
    }
}

#[test]
fn fuzzed_mangled_symbols_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0xDE3A_5717_0001_0002);
    for _ in 0..30_000 {
        let s: String = fuzz_str(&mut rng);
        exercise_str(&s);
    }
}
