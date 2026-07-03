#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_py_marshal::{PyVersion, dump_reftable, load, load_with_reftable, read_pyc};

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

const VERSIONS: [PyVersion; 4] = [
    PyVersion::PY15,
    PyVersion::PY27,
    PyVersion::PY37,
    PyVersion {
        major: 3,
        minor: 11,
    },
];

fn marshal_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.push(b'(');
    v.extend_from_slice(&3u32.to_le_bytes());
    v.push(b'i');
    v.extend_from_slice(&7i32.to_le_bytes());
    v.push(b's');
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(b"hi");
    v.push(b'N');
    v
}

fn pyc_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0x0a0d_0d33u32.to_le_bytes());
    v.extend_from_slice(&[0u8; 12]);
    v.extend_from_slice(&marshal_seed());
    v
}

fn nested_collection_bomb(depth: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(depth * 5);
    for _ in 0..depth {
        v.push(b'(');
        v.extend_from_slice(&1u32.to_le_bytes());
    }
    v.push(b'N');
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
            let collection_tags: [u8; 6] = [b'(', b'[', b'{', b'<', b'>', b'c'];
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 3 {
                    *b = collection_tags[rng.next_usize(collection_tags.len())];
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
    let _ = read_pyc(bytes);
    for version in VERSIONS {
        let _ = load(bytes, version);
        let _ = load_with_reftable(bytes, version);
        let _ = dump_reftable(bytes, version);
    }
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x4d59_5f72_6e64_0001);
    for _ in 0..8_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn mutated_seed_inputs_never_panic() {
    let seeds: [Vec<u8>; 2] = [marshal_seed(), pyc_seed()];
    let mut rng: Xorshift64 = Xorshift64::new(0x6d61_7273_6861_6c21);
    for seed in &seeds {
        for _ in 0..10_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
    }
}

#[test]
fn deep_nesting_does_not_overflow_stack() {
    for depth in [64usize, 255, 256, 257, 1_000, 100_000, 5_000_000] {
        let bomb: Vec<u8> = nested_collection_bomb(depth);
        for version in VERSIONS {
            let _ = load(&bomb, version);
        }
        let _ = read_pyc(&bomb);
    }
}
