#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_shell::{
    analyze_stomp, deobfuscate_vbs, detect, disassemble_pcode, disassemble_pcode_real,
    extract_from_bytes, parse_ast, reverse_psobf, vba_project_bin_from_bytes,
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
