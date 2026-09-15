#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::panic::catch_unwind;

use disrobe_pass_dotnet::pe::{self, PE32_MAGIC, PeImage};

const NT_SIGNATURE: u32 = 0x0000_4550;

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

fn craft(number_of_sections: u16, opt_size: u16, tail: usize) -> Vec<u8> {
    let pe_off: usize = 0x80;
    let len: usize = (pe_off + 24 + opt_size as usize + tail).max(pe_off + 26);
    let mut bytes: Vec<u8> = vec![0u8; len];
    bytes[0] = 0x4D;
    bytes[1] = 0x5A;
    bytes[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    bytes[pe_off..pe_off + 4].copy_from_slice(&NT_SIGNATURE.to_le_bytes());
    bytes[pe_off + 4..pe_off + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
    bytes[pe_off + 6..pe_off + 8].copy_from_slice(&number_of_sections.to_le_bytes());
    bytes[pe_off + 20..pe_off + 22].copy_from_slice(&opt_size.to_le_bytes());
    let opt_start: usize = pe_off + 24;
    bytes[opt_start..opt_start + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
    bytes
}

#[test]
fn malformed_pe_battery_never_panics() {
    let wrong_magic: Vec<u8> = {
        let mut base: Vec<u8> = craft(1, 96, 40);
        let opt_start: usize = 0x80 + 24;
        base[opt_start..opt_start + 2].copy_from_slice(&0x1234u16.to_le_bytes());
        base
    };
    let battery: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x4D],
        vec![0x4D, 0x5A],
        vec![0u8; 64],
        vec![0x4D, 0x5A, 0, 0, 0, 0, 0, 0],
        craft(0xFFFF, 96, 0),
        craft(0xFFFF, 0xFFFF, 0),
        craft(0x7FFF, 96, 40),
        craft(0, 96, 0),
        craft(0xFFFF, 96, 39),
        craft(1, 0, 0),
        wrong_magic,
    ];
    for (i, sample) in battery.into_iter().enumerate() {
        let outcome: std::thread::Result<disrobe_pass_dotnet::Result<PeImage>> =
            catch_unwind(move || pe::parse(&sample));
        assert!(outcome.is_ok(), "sample {i} panicked");
    }
}

#[test]
fn random_bytes_smoke_never_panics() {
    let mut rng: Xorshift64 = Xorshift64::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let len: usize = rng.next_usize(384);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let outcome: std::thread::Result<disrobe_pass_dotnet::Result<PeImage>> =
            catch_unwind(move || pe::parse(&bytes));
        assert!(outcome.is_ok(), "random input panicked");
    }
}

#[test]
fn corpus_dll_parses_deterministically_with_bounded_capacity() {
    let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/HelloApp.dll");
    let bytes: Vec<u8> = std::fs::read(&path).expect("corpus fixture");
    let first: PeImage = pe::parse(&bytes).expect("well-formed managed pe parses");
    let second: PeImage = pe::parse(&bytes).expect("re-parse");
    assert_eq!(first, second);
    assert_eq!(first.sections.len(), first.number_of_sections as usize);
    assert!(first.sections.capacity() <= bytes.len() / 40 + 1);
}
