#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_nativelang::{analyze, demangle_crystal, demangle_d, demangle_nim, demangle_zig};

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

fn elf64_seed() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; 256];
    v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[16..18].copy_from_slice(&2u16.to_le_bytes());
    v[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    v[20..24].copy_from_slice(&1u32.to_le_bytes());
    v
}

fn fuzz_mangled(rng: &mut Xorshift64) -> String {
    let len: usize = rng.next_usize(120);
    let alphabet: &[u8] =
        b"_ZN0123456789abcdefghijklmnopqrstuvwxyzABCDEF$.@*<>,()[]\xc3\xa9\xf0\x9f\x98\x80";
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
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
            let len: usize = rng.next_usize(512);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    out
}

#[test]
fn pure_random_images_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x4E47_0001_4E47_0001);
    for _ in 0..4_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let _ = analyze(&bytes);
    }
}

#[test]
fn mutated_elf_seeds_never_panic() {
    let seeds: [Vec<u8>; 2] = [elf64_seed(), Vec::new()];
    let mut rng: Xorshift64 = Xorshift64::new(0x4E47_0102_0304_0506);
    for seed in &seeds {
        for _ in 0..3_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            let _ = analyze(&mutated);
        }
    }
}

#[test]
fn fuzzed_mangled_symbols_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x4E47_DECA_FF01_0203);
    for _ in 0..40_000 {
        let s: String = fuzz_mangled(&mut rng);
        let _ = demangle_nim(&s);
        let _ = demangle_zig(&s);
        let _ = demangle_crystal(&s);
        let _ = demangle_d(&s);
    }
}
