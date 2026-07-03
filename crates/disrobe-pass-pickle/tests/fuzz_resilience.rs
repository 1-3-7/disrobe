#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_pickle::{
    analyze_polyglot, analyze_safety, disassemble, execute, looks_like_pickle, to_python,
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

const SEED_INPUTS: &[&[u8]] = &[
    b"\x80\x02K\x07.",
    b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01a\x94.",
    b"(lp0\nI1\naI2\na.",
    b"\x80\x05\x95\x00\x00\x00\x00\x00\x00\x00\x00}\x94.",
    b"]q\x00(K\x01K\x02K\x03e.",
    b"\x80\x03cbuiltins\nexec\nq\x00X\x04\x00\x00\x00pass\x85\x86.",
    b"\x80\x02}q\x00(U\x01aq\x01K\x01u.",
    b"c__main__\nfoo\n(t\x81.",
    b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94.",
];

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    let kind: u64 = rng.next_u64() % 6;
    match kind {
        0 => {
            if !out.is_empty() {
                let idx: usize = rng.next_usize(out.len());
                out[idx] ^= 1u8 << (rng.next_usize(8));
            }
        }
        1 => {
            if !out.is_empty() {
                let cut: usize = rng.next_usize(out.len());
                out.truncate(cut);
            }
        }
        2 => {
            let at: usize = if out.is_empty() {
                0
            } else {
                rng.next_usize(out.len())
            };
            let count: usize = rng.next_usize(64);
            for _ in 0..count {
                out.insert(at.min(out.len()), rng.next_byte());
            }
        }
        3 => {
            let count: usize = rng.next_usize(out.len().max(1));
            for _ in 0..count {
                let idx: usize = rng.next_usize(out.len().max(1));
                if idx < out.len() {
                    out[idx] = rng.next_byte();
                }
            }
        }
        4 => {
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 3 {
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
    let _ = looks_like_pickle(bytes);
    let _ = analyze_polyglot(bytes);
    if let Ok(dis) = disassemble(bytes)
        && let Ok(trace) = execute(&dis)
    {
        let _ = to_python(&trace.result);
        let _ = analyze_safety(&trace);
    }
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn mutated_seed_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0xD1B5_4A32_D192_ED03);
    for seed in SEED_INPUTS {
        for _ in 0..4_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
    }
}

#[test]
fn structured_opcode_storms_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x2545_F491_4F6C_DD1D);
    for _ in 0..20_000 {
        let len: usize = 2 + rng.next_usize(256);
        let mut bytes: Vec<u8> = Vec::with_capacity(len + 2);
        bytes.push(0x80);
        bytes.push((rng.next_byte() % 6) + 1);
        for _ in 0..len {
            bytes.push(rng.next_byte());
        }
        bytes.push(b'.');
        exercise(&bytes);
    }
}
