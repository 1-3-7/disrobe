#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_sourcedefender::{
    InlinedExtractOptions, ascii85_decode, base85_decode_rfc1924, classify_container,
    decode_armored_line, decrypt_pye, extract_inlined, hex_decode, locate_inlined_blocks,
    parse_msgpack_envelope, parse_pye_frame, recover_layered,
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

fn ascii85_alphabet(rng: &mut Xorshift64) -> Vec<u8> {
    let len: usize = rng.next_usize(160);
    (0..len)
        .map(|_| {
            if rng.next_u64().trailing_zeros() >= 2 {
                rng.next_byte()
            } else {
                0x21 + (rng.next_byte() % 0x55)
            }
        })
        .collect()
}

fn pye_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"-----BEGIN SOURCEDEFENDER-----\n");
    v.extend_from_slice(b"AAAAAAAAAAAA\n");
    v.extend_from_slice(b"-----END SOURCEDEFENDER-----\n");
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
            let len: usize = rng.next_usize(512);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    out
}

fn exercise(bytes: &[u8]) {
    let _ = base85_decode_rfc1924(bytes);
    let _ = ascii85_decode(bytes);
    let _ = decode_armored_line(bytes);
    let _ = hex_decode(bytes);
    let _ = parse_msgpack_envelope(bytes);
    let _ = decrypt_pye(bytes, "fuzz.pye");
    let _ = recover_layered(bytes, "fuzz.pye");
    let _ = classify_container(bytes);
    if let Ok(s) = core::str::from_utf8(bytes) {
        let _ = parse_pye_frame(s);
        let _ = locate_inlined_blocks(s);
        let _ = extract_inlined(s, "fuzz.py", InlinedExtractOptions::default());
    }
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x50DE_FE0D_0001_0002);
    for _ in 0..6_000 {
        let len: usize = rng.next_usize(512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn ascii85_alphabet_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x50DE_A855_0001_0002);
    for _ in 0..20_000 {
        let bytes: Vec<u8> = ascii85_alphabet(&mut rng);
        let _ = base85_decode_rfc1924(&bytes);
        let _ = ascii85_decode(&bytes);
        let _ = decode_armored_line(&bytes);
    }
}

#[test]
fn mutated_pye_envelopes_never_panic() {
    let seeds: [Vec<u8>; 2] = [pye_seed(), Vec::new()];
    let mut rng: Xorshift64 = Xorshift64::new(0x50DE_9099_0304_0506);
    for seed in &seeds {
        for _ in 0..4_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
    }
}
