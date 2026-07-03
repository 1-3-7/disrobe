#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_beam::chunks::{self, CodeChunk, LineChunk, LiteralChunk, StringTable};
use disrobe_pass_beam::ez::{EzArchive, EzQuota};
use disrobe_pass_beam::file::{BeamFile, RawBeam};
use disrobe_pass_beam::{decode_etf, disassemble};

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

fn beam_seed() -> Vec<u8> {
    let mut chunks_blob: Vec<u8> = Vec::new();
    chunks_blob.extend_from_slice(b"AtU8");
    chunks_blob.extend_from_slice(&8u32.to_be_bytes());
    chunks_blob.extend_from_slice(&1u32.to_be_bytes());
    chunks_blob.push(3);
    chunks_blob.extend_from_slice(b"mod");
    let form_len: u32 = (4 + chunks_blob.len()) as u32;
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"FOR1");
    v.extend_from_slice(&form_len.to_be_bytes());
    v.extend_from_slice(b"BEAM");
    v.extend_from_slice(&chunks_blob);
    v
}

fn beam_chunk_boundary_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"FOR1");
    let form_len: u32 = 8;
    v.extend_from_slice(&form_len.to_be_bytes());
    v.extend_from_slice(b"BEAM");
    v.extend_from_slice(b"At");
    v.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    v
}

fn etf_seed() -> Vec<u8> {
    vec![131, 104, 2, 97, 1, 97, 2]
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
            let at: usize = if out.is_empty() {
                0
            } else {
                rng.next_usize(out.len())
            };
            let count: usize = rng.next_usize(48);
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
    let _ = RawBeam::parse(bytes);
    let _ = BeamFile::parse(bytes);
    let _ = decode_etf(bytes);
    let _ = chunks::parse_export_table(bytes);
    let _ = chunks::parse_import_table(bytes);
    let _ = chunks::parse_local_table(bytes);
    let _ = chunks::parse_fun_table(bytes);
    let _ = LineChunk::parse(bytes);
    let _ = LiteralChunk::parse(bytes);
    let _ = StringTable::parse(bytes);
    let code: CodeChunk = CodeChunk {
        sub_size: 0,
        instruction_set: 0,
        opcode_max: 200,
        num_labels: 0,
        num_functions: 0,
        code: bytes.to_vec(),
    };
    let _ = disassemble(&code);
    let _ = EzArchive::parse(bytes);
    let _ = EzArchive::parse_with_quota(bytes, EzQuota::default());
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0xBEA3_0001_BEA3_0001);
    for _ in 0..8_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn mutated_seed_inputs_never_panic() {
    let seeds: [Vec<u8>; 4] = [
        beam_seed(),
        beam_chunk_boundary_seed(),
        etf_seed(),
        Vec::new(),
    ];
    let mut rng: Xorshift64 = Xorshift64::new(0xBEA3_0102_0304_0506);
    for seed in &seeds {
        for _ in 0..6_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
    }
}

#[test]
fn chunk_length_at_form_boundary_does_not_underflow() {
    let seed: Vec<u8> = beam_chunk_boundary_seed();
    let _ = RawBeam::parse(&seed);
    let _ = BeamFile::parse(&seed);
}

#[test]
fn extended_compact_length_tag_does_not_recurse_forever() {
    let code: CodeChunk = CodeChunk {
        sub_size: 0,
        instruction_set: 0,
        opcode_max: 200,
        num_labels: 0,
        num_functions: 0,
        code: vec![1, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8],
    };
    let _ = disassemble(&code);
}
