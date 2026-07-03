#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_pyinstaller::{MEI_MAGIC, extract_archive, extract_pyz, find_cookie, walk_toc};

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

fn pyinstaller_seed() -> Vec<u8> {
    let mut toc: Vec<u8> = Vec::new();
    let name: &[u8] = b"entry\x00\x00\x00";
    let entry_size: u32 = 18 + name.len() as u32;
    toc.extend_from_slice(&entry_size.to_be_bytes());
    toc.extend_from_slice(&0u32.to_be_bytes());
    toc.extend_from_slice(&4u32.to_be_bytes());
    toc.extend_from_slice(&4u32.to_be_bytes());
    toc.push(0);
    toc.push(b'b');
    toc.extend_from_slice(name);

    let mut image: Vec<u8> = Vec::new();
    image.extend_from_slice(b"DATA");
    let toc_offset: u32 = image.len() as u32;
    image.extend_from_slice(&toc);
    let toc_length: u32 = toc.len() as u32;

    let cookie_offset: usize = image.len();
    image.extend_from_slice(MEI_MAGIC);
    let length_of_package: u32 = (cookie_offset + 88) as u32;
    image.extend_from_slice(&length_of_package.to_be_bytes());
    image.extend_from_slice(&toc_offset.to_be_bytes());
    image.extend_from_slice(&toc_length.to_be_bytes());
    image.extend_from_slice(&311u32.to_be_bytes());
    let mut libname: Vec<u8> = b"python3.11".to_vec();
    libname.resize(64, 0);
    image.extend_from_slice(&libname);
    image
}

fn pyz_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"PYZ\x00");
    v.extend_from_slice(&0x0a0du32.to_be_bytes());
    v.extend_from_slice(&64u32.to_be_bytes());
    while v.len() < 64 {
        v.push(0);
    }
    v
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
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 3 {
                    *b = 0;
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

fn exercise(bytes: &[u8]) {
    if let Ok(cookie) = find_cookie(bytes) {
        let _ = walk_toc(bytes, &cookie);
    }
    let _ = extract_archive(bytes);
    let _ = extract_pyz(bytes);
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x0F1E_2D3C_4B5A_6978);
    for _ in 0..10_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn mutated_seed_inputs_never_panic() {
    let seeds: [Vec<u8>; 2] = [pyinstaller_seed(), pyz_seed()];
    let mut rng: Xorshift64 = Xorshift64::new(0x7766_5544_3322_1100);
    for seed in &seeds {
        for _ in 0..15_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
    }
}
