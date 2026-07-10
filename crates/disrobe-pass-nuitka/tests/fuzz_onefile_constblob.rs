#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

use disrobe_pass_nuitka::{
    ConstantsPool, NuitkaConstants, build_manifest, build_surface, classify,
    decode_build_constants, decode_bytecode_table, decode_const_file, decompile_bytes,
    demangle_function, detect_authenticode, detect_in_bytes, disassemble_module_stats, emit_python,
    extract_for_classification, extract_onefile, extract_onefile_streaming, extract_variant,
    lift_native_bodies, locate_onefile_payload, map_names, parse_c_module, parse_constant_manifest,
    parse_constants, reconstruct_skeleton, recover_frozen_bytecode, scan_build_info,
    scan_c_source_markers, scan_constants_blob, scan_plugins, scan_symbols,
};

static SUPPRESS_HOOK: Once = Once::new();

fn suppress_panic_output() {
    SUPPRESS_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_info: &std::panic::PanicHookInfo<'_>| {}));
    });
}

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

const MAX_INPUT: usize = 8 * 1024;

fn clamp_input(mut v: Vec<u8>) -> Vec<u8> {
    if v.len() > MAX_INPUT {
        v.truncate(MAX_INPUT);
    }
    v
}

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    match rng.next_u64() % 7 {
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
            let count: usize = rng.next_usize(out.len().max(1)).min(64);
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
            let extra: usize = rng.next_usize(256);
            for _ in 0..extra {
                out.push(rng.next_byte());
            }
        }
        5 => {
            if !out.is_empty() {
                let at: usize = rng.next_usize(out.len());
                let run: usize = rng.next_usize(out.len() - at + 1);
                for slot in out.iter_mut().skip(at).take(run) {
                    *slot = 0u8;
                }
            }
        }
        _ => {
            let len: usize = rng.next_usize(512);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    clamp_input(out)
}

fn guard<F: FnOnce()>(label: &str, f: F) {
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(f));
    assert!(result.is_ok(), "panic in {label}");
}

fn exercise(bytes: &[u8], rng: &mut Xorshift64) {
    guard("detect_in_bytes", || {
        let _ = detect_in_bytes(bytes);
    });
    guard("parse_constants", || {
        let _ = parse_constants(bytes);
    });
    guard("scan_constants_blob", || {
        let _ = scan_constants_blob(bytes);
    });
    guard("parse_constant_manifest", || {
        let _ = parse_constant_manifest(bytes);
    });
    guard("scan_c_source_markers", || {
        let _ = scan_c_source_markers(bytes);
    });
    guard("scan_build_info", || {
        let _ = scan_build_info(bytes);
    });
    guard("scan_plugins", || {
        let _ = scan_plugins(bytes);
    });
    guard("scan_symbols", || {
        let _ = scan_symbols(bytes);
    });
    guard("detect_authenticode", || {
        let _ = detect_authenticode(bytes);
    });
    guard("extract_variant", || {
        let _ = extract_variant(bytes);
    });
    guard("classify+extract_for_classification", || {
        if let Ok(classification) = classify(bytes) {
            let _ = extract_for_classification(bytes, &classification);
        }
    });
    guard("locate_onefile_payload", || {
        let _ = locate_onefile_payload(bytes);
    });
    guard("build_manifest", || {
        let _ = build_manifest(bytes);
    });
    guard("decode_bytecode_table", || {
        let _ = decode_bytecode_table(bytes, None);
    });
    guard("recover_frozen_bytecode", || {
        let _ = recover_frozen_bytecode(bytes, None);
    });
    guard("disassemble_module_stats", || {
        let _ = disassemble_module_stats("<fuzz>", bytes);
    });
    guard("decompile_bytes", || {
        let _ = decompile_bytes(bytes);
    });
    guard("native-body+skeleton+name-map", || {
        let constants: NuitkaConstants = parse_constants(bytes);
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
    });

    let offsets: [usize; 4] = [
        0,
        rng.next_usize(bytes.len() + 8),
        bytes.len().saturating_sub(1),
        bytes.len() + 1,
    ];
    for off in offsets {
        guard("extract_onefile", || {
            let _ = extract_onefile(bytes, off);
        });
        guard("extract_onefile_streaming", || {
            let _ = extract_onefile_streaming(bytes, off, &mut |_e| Ok(()));
        });
    }

    guard("decode_const_file", || {
        let _ = decode_const_file(bytes, "fuzz.const", "fuzz");
    });
    guard("decode_build_constants", || {
        let files: Vec<(String, Vec<u8>, String)> =
            vec![("fuzz.const".to_owned(), bytes.to_vec(), "fuzz".to_owned())];
        let _ = decode_build_constants(&files);
    });

    if let Ok(text) = core::str::from_utf8(bytes) {
        guard("parse_c_module", || {
            let _ = parse_c_module(text);
        });
        guard("build_surface+emit_python", || {
            let pool: ConstantsPool =
                decode_const_file(bytes, "fuzz.const", "fuzz").unwrap_or_default();
            if let Ok(c_module) = parse_c_module(text)
                && let Ok(surface) = build_surface(&c_module, &pool, Some(text))
            {
                let _ = emit_python(&surface);
            }
        });
    }
}

fn committed_fixtures() -> Vec<Vec<u8>> {
    let root: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates: [std::path::PathBuf; 5] = [
        root.join("tests/fixtures/onefile_header_slice.kax"),
        root.join("tests/fixtures/planted_marker.txt"),
        root.join("../../corpus/python/nuitka/module/hello.build/module.hello.const"),
        root.join("../../corpus/python/nuitka/module/hello.build/blobs/__constant.txt"),
        root.join("../../corpus/python/nuitka/console-disable/hello.build/blobs/__constant.txt"),
    ];
    candidates
        .iter()
        .filter_map(|p: &std::path::PathBuf| std::fs::read(p).ok())
        .map(clamp_input)
        .collect()
}

fn synthetic_seeds() -> Vec<Vec<u8>> {
    let mut win: Vec<u8> = b"KAX".to_vec();
    for unit in "mod.dll".encode_utf16() {
        win.extend_from_slice(&unit.to_le_bytes());
    }
    win.extend_from_slice(&[0u8, 0u8]);
    win.extend_from_slice(&5u64.to_le_bytes());
    win.extend_from_slice(b"MZdat");
    win.extend_from_slice(&[0u8, 0u8]);

    let mut posix: Vec<u8> = b"KAX".to_vec();
    posix.extend_from_slice(b"bin/app\0");
    posix.push(0u8);
    posix.extend_from_slice(&4u64.to_le_bytes());
    posix.extend_from_slice(b"\x7fELF");
    posix.push(0u8);

    let pickle_int: Vec<u8> = b"\x80\x05K\x07.".to_vec();
    let pickle_str: Vec<u8> = b"\x80\x05\x8c\x03foo\x94.".to_vec();

    let mut const_chunk: Vec<u8> = Vec::new();
    const_chunk.extend_from_slice(b"mod\0");
    const_chunk.extend_from_slice(&8u32.to_le_bytes());
    const_chunk.extend_from_slice(&1u16.to_le_bytes());
    const_chunk.push(0x76);
    const_chunk.push(0x04);
    const_chunk.extend_from_slice(b"name");

    vec![win, posix, pickle_int, pickle_str, const_chunk]
}

#[test]
fn carve_and_constblob_entries_never_panic() {
    suppress_panic_output();
    let mut seeds: Vec<Vec<u8>> = committed_fixtures();
    seeds.extend(synthetic_seeds());
    seeds.push(Vec::new());

    let mut rng: Xorshift64 = Xorshift64::new(0x4E55_4954_4B41_0001);
    for seed in &seeds {
        for _ in 0..900 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            let mut local: Xorshift64 = Xorshift64::new(rng.next_u64());
            exercise(&mutated, &mut local);
        }
    }
}

#[test]
fn pure_random_carve_and_constblob_never_panic() {
    suppress_panic_output();
    let mut rng: Xorshift64 = Xorshift64::new(0x4E55_4954_4B41_0002);
    for _ in 0..3_000 {
        let len: usize = rng.next_usize(2048);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let mut local: Xorshift64 = Xorshift64::new(rng.next_u64());
        exercise(&bytes, &mut local);
    }
}
