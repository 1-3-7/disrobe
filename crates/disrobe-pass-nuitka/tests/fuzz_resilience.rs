#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_nuitka::{
    NuitkaConstants, build_manifest, decode_bytecode_table, decompile_bytes, demangle_function,
    detect_authenticode, detect_in_bytes, disassemble_module_stats, extract_onefile,
    extract_variant, lift_native_bodies, locate_onefile_payload, map_names, parse_c_module,
    parse_constant_manifest, parse_constants, reconstruct_skeleton, recover_frozen_bytecode,
    scan_build_info, scan_c_source_markers, scan_constants_blob, scan_plugins,
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

fn onefile_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"KAX");
    v.push(0);
    v.extend_from_slice(b"mod.py\0");
    v.extend_from_slice(&8u64.to_le_bytes());
    v.extend_from_slice(b"contents");
    while v.len() < 96 {
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

fn exercise(bytes: &[u8], rng: &mut Xorshift64) {
    let _ = detect_in_bytes(bytes);
    let constants: NuitkaConstants = parse_constants(bytes);
    let _ = scan_constants_blob(bytes);
    let _ = parse_constant_manifest(bytes);
    let _ = scan_c_source_markers(bytes);
    let _ = scan_build_info(bytes);
    let _ = scan_plugins(bytes);
    let _ = detect_authenticode(bytes);
    let _ = extract_variant(bytes);
    let _ = locate_onefile_payload(bytes);
    let _ = build_manifest(bytes);
    let _ = decode_bytecode_table(bytes, None);
    let _ = recover_frozen_bytecode(bytes, None);
    let _ = disassemble_module_stats("<fuzz>", bytes);
    let _ = lift_native_bodies(bytes, &constants);
    let _ = reconstruct_skeleton(&constants);
    let names: Vec<String> = constants
        .modules
        .iter()
        .flat_map(|module| module.strings.iter().cloned())
        .take(64)
        .collect();
    let _ = map_names("<fuzz>", bytes, &names);
    if let Some(name) = names.first() {
        let _ = demangle_function(name);
    }
    let _ = decompile_bytes(bytes);
    let off: usize = if bytes.is_empty() {
        0
    } else {
        rng.next_usize(bytes.len() + 8)
    };
    let _ = extract_onefile(bytes, off);
    if let Ok(s) = core::str::from_utf8(bytes) {
        let _ = parse_c_module(s);
    }
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x4E55_1714_0001_0002);
    for _ in 0..4_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let mut local: Xorshift64 = Xorshift64::new(rng.next_u64());
        exercise(&bytes, &mut local);
    }
}

#[test]
fn mutated_onefile_seeds_never_panic() {
    let seeds: [Vec<u8>; 2] = [onefile_seed(), Vec::new()];
    let mut rng: Xorshift64 = Xorshift64::new(0x4E55_9099_0304_0506);
    for seed in &seeds {
        for _ in 0..3_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            let mut local: Xorshift64 = Xorshift64::new(rng.next_u64());
            exercise(&mutated, &mut local);
        }
    }
}
