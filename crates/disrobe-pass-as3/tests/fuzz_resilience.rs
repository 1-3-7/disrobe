#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_as3::abc;
use disrobe_pass_as3::swf;

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

fn abc_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&16u16.to_le_bytes());
    v.extend_from_slice(&46u16.to_le_bytes());
    v.extend(std::iter::repeat_n(0x01u8, 8));
    v
}

fn swf_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"FWS");
    v.push(13);
    v.extend_from_slice(&64u32.to_le_bytes());
    while v.len() < 64 {
        v.push(0);
    }
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
                out.truncate(rng.next_usize(out.len()));
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

fn exercise(bytes: &[u8]) {
    let _ = abc::parse(bytes);
    let _ = abc::disasm(bytes);
    let _ = swf::detect(bytes);
    let _ = swf::parse(bytes);
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0xa53b_c0de_a53b_c0de);
    for _ in 0..12_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn mutated_seed_inputs_never_panic() {
    let seeds: [Vec<u8>; 2] = [abc_seed(), swf_seed()];
    let mut rng: Xorshift64 = Xorshift64::new(0x5346_5741_5346_5741);
    for seed in &seeds {
        for _ in 0..10_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
    }
}
