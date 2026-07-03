#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_mobile::apk_recon;
use disrobe_pass_mobile::arsc;
use disrobe_pass_mobile::axml;
use disrobe_pass_mobile::hermes;
use disrobe_pass_mobile::ios;
use disrobe_pass_mobile::react_native;
use disrobe_pass_mobile::xamarin;

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

fn axml_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0x0003u16.to_le_bytes());
    v.extend_from_slice(&0x0008u16.to_le_bytes());
    v.extend_from_slice(&0x0000_0040u32.to_le_bytes());
    v.extend_from_slice(&0x0001u16.to_le_bytes());
    v.extend_from_slice(&0x001cu16.to_le_bytes());
    v.extend_from_slice(&0x0000_0030u32.to_le_bytes());
    v.extend_from_slice(&0x0000_0002u32.to_le_bytes());
    v.extend_from_slice(&0x0000_0000u32.to_le_bytes());
    v.extend_from_slice(&0x0000_0100u32.to_le_bytes());
    v.extend_from_slice(&0x0000_0000u32.to_le_bytes());
    v.extend_from_slice(&0x0000_0028u32.to_le_bytes());
    v.extend_from_slice(&0x0000_002cu32.to_le_bytes());
    while v.len() < 0x40 {
        v.push(0);
    }
    v
}

fn arsc_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0x0002u16.to_le_bytes());
    v.extend_from_slice(&0x000cu16.to_le_bytes());
    v.extend_from_slice(&0x0000_0040u32.to_le_bytes());
    v.extend_from_slice(&0x0000_0001u32.to_le_bytes());
    while v.len() < 0x40 {
        v.push(0);
    }
    v
}

fn hermes_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&hermes::HERMES_MAGIC.to_le_bytes());
    v.extend_from_slice(&96u32.to_le_bytes());
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

fn macho_fat_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
    v.extend_from_slice(&2u32.to_be_bytes());
    v.extend_from_slice(&[0u8; 40]);
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
    let _ = axml::parse(bytes);
    let _ = arsc::parse(bytes);
    let _ = hermes::parse_header(bytes);
    let _ = hermes::parse(bytes);
    let _ = apk_recon::analyze(bytes);
    let _ = ios::walk_macho_fat(bytes);
    let _ = ios::extract_ipa(bytes);
    let _ = xamarin::parse_assembly_store_header(bytes);
    let _ = xamarin::extract_xamarin_bundle(bytes);
    let _ = react_native::detect_bundle_format(bytes);
    let _ = react_native::extract_from_apk_or_ipa(bytes);
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x1357_9BDF_2468_ACE0);
    for _ in 0..6_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

fn fixture_entry(rel: &str, name: &str) -> Vec<u8> {
    use std::io::Read as _;
    use std::path::PathBuf;
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push(rel);
    let Ok(bytes) = std::fs::read(&p) else {
        return Vec::new();
    };
    let cur: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(bytes);
    let Ok(mut z) = zip::ZipArchive::new(cur) else {
        return Vec::new();
    };
    let Ok(mut f) = z.by_name(name) else {
        return Vec::new();
    };
    let mut out: Vec<u8> = Vec::new();
    let _ = f.read_to_end(&mut out);
    out
}

#[test]
fn mutated_seed_inputs_never_panic() {
    let seeds: [Vec<u8>; 8] = [
        axml_seed(),
        arsc_seed(),
        hermes_seed(),
        zip_seed(),
        macho_fat_seed(),
        fixture_entry("corpus/apk/fixture-rich.apk", "AndroidManifest.xml"),
        fixture_entry("corpus/apk/fixture-rich.apk", "resources.arsc"),
        Vec::new(),
    ];
    let mut rng: Xorshift64 = Xorshift64::new(0xABCD_1234_5678_9F01);
    for seed in &seeds {
        for _ in 0..3_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
    }
}
