#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Once;

use disrobe_pass_pyfreeze::common::pyc::fingerprint;
use disrobe_pass_pyfreeze::common::shebang;
use disrobe_pass_pyfreeze::common::zip_tail;
use disrobe_pass_pyfreeze::py2exe::overlay::extract_overlay_zip;
use disrobe_pass_pyfreeze::py2exe::pe::{
    extract_pythonscript_resource, looks_like_pe, sniff_python_version,
};
use disrobe_pass_pyfreeze::py2exe::scriptinfo::parse as parse_scriptinfo;
use disrobe_pass_pyfreeze::pyoxidizer::looks_like_pyoxidizer;
use disrobe_pass_pyfreeze::pyoxidizer::signatures::{
    extract_modules, extract_resources_blob, infer_python_version, parse_packed_resources, scan,
};
use disrobe_pass_pyfreeze::{detect_bytes, recover_bytecode, recover_raw_marshal, surface_native};

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

static SILENCE_HOOK: Once = Once::new();

fn silence_panics() {
    SILENCE_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_info: &std::panic::PanicHookInfo<'_>| {}));
    });
}

fn guard<F: FnOnce()>(label: &str, input: &[u8], f: F) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        let head: Vec<u8> = input.iter().take(64).copied().collect();
        panic!(
            "pyfreeze fuzz panic in {label}; input len={} head={head:02x?}",
            input.len()
        );
    }
}

fn exercise(bytes: &[u8], rng: &mut Xorshift64) {
    guard("detect_bytes", bytes, || {
        let _ = detect_bytes(bytes, None);
    });
    guard("recover_bytecode", bytes, || {
        let _ = recover_bytecode("fuzz", bytes);
    });
    guard("surface_native", bytes, || {
        let _ = surface_native("fuzz", bytes);
    });
    let major: u8 = (rng.next_byte() % 4) + 2;
    let minor: u8 = rng.next_byte() % 16;
    guard("recover_raw_marshal", bytes, || {
        let _ = recover_raw_marshal("fuzz", bytes, major, minor);
    });
    guard("pyoxidizer.scan", bytes, || {
        let _ = scan(bytes);
    });
    guard("pyoxidizer.looks_like_pyoxidizer", bytes, || {
        let _ = looks_like_pyoxidizer(bytes);
    });
    guard("pyoxidizer.infer_python_version", bytes, || {
        let _ = infer_python_version(bytes);
    });
    guard("pyoxidizer.extract_resources_blob", bytes, || {
        let _ = extract_resources_blob(bytes);
    });
    guard("pyoxidizer.parse_packed_resources", bytes, || {
        let _ = parse_packed_resources(bytes);
    });
    guard("pyoxidizer.extract_modules", bytes, || {
        let _ = extract_modules(bytes);
    });
    guard("py2exe.looks_like_pe", bytes, || {
        let _ = looks_like_pe(bytes);
    });
    guard("py2exe.sniff_python_version", bytes, || {
        let _ = sniff_python_version(bytes);
    });
    guard("py2exe.extract_pythonscript_resource", bytes, || {
        let _ = extract_pythonscript_resource(bytes);
    });
    guard("py2exe.extract_overlay_zip", bytes, || {
        let _ = extract_overlay_zip(bytes);
    });
    guard("py2exe.scriptinfo.parse", bytes, || {
        let _ = parse_scriptinfo(bytes);
    });
    guard("common.zip_tail.locate", bytes, || {
        let _ = zip_tail::locate(bytes);
    });
    guard("common.zip_tail.is_likely_trailing_zip", bytes, || {
        let _ = zip_tail::is_likely_trailing_zip(bytes);
    });
    guard("common.pyc.fingerprint", bytes, || {
        let _ = fingerprint(bytes);
    });
    guard("common.shebang.parse", bytes, || {
        let _ = shebang::parse(bytes);
    });
    #[cfg(feature = "chain")]
    exercise_chain(bytes);
}

#[cfg(feature = "chain")]
fn exercise_chain(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::chain::{DetectContext, Detector, Pass};
    use disrobe_pass_pyfreeze::chain_detector::{PyfreezeDetector, PyfreezePass};

    guard("chain.detect", bytes, || {
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let _ = PyfreezeDetector.detect(&ctx);
    });
    let artifact: Artifact = Artifact::new(disrobe_core::Rung::Raw, bytes.to_vec(), [0u8; 32]);
    guard("chain.run", bytes, || {
        let _ = PyfreezePass.run(&artifact);
    });
    guard("chain.extract_children", bytes, || {
        let _ = PyfreezePass.extract_children(&artifact);
    });
}

fn pyc_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&[0xa7, 0x0d, 0x0d, 0x0a]);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.push(b'c');
    while v.len() < 96 {
        v.push(0);
    }
    v
}

fn py2exe_scriptinfo_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0x7856_3412u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(b"app.zip\0");
    v.extend_from_slice(&[0xE3, 0x00, 0x00, 0x00]);
    v
}

fn minimal_pe_seed() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; 0x80];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    v[0x40..0x44].copy_from_slice(b"PE\0\0");
    v.extend_from_slice(b"PYTHONSCRIPT");
    v.extend_from_slice(&0x7856_3412u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(b"app.zip\0python314.dll");
    v
}

const BLOB_START_OF_ENTRY: u8 = 0x01;
const BLOB_RESOURCE_FIELD_TYPE: u8 = 0x02;
const BLOB_RAW_PAYLOAD_LENGTH: u8 = 0x03;
const BLOB_INTERIOR_PADDING: u8 = 0x04;
const BLOB_END_OF_ENTRY: u8 = 0xff;
const BLOB_END_OF_INDEX: u8 = 0x00;
const PADDING_NONE: u8 = 0x01;
const RES_START_OF_ENTRY: u8 = 0x01;
const RES_NAME: u8 = 0x03;
const RES_IS_PYTHON_MODULE: u8 = 0x16;
const RES_IN_MEMORY_BYTECODE: u8 = 0x07;
const RES_END_OF_ENTRY: u8 = 0xff;
const RES_END_OF_INDEX: u8 = 0x00;

fn pyoxidizer_v3_seed() -> Vec<u8> {
    let name: &[u8] = b"mod";
    let bytecode: &[u8] = b"BYTECODE";
    let mut name_section: Vec<u8> = Vec::new();
    name_section.extend_from_slice(name);
    let mut bytecode_section: Vec<u8> = Vec::new();
    bytecode_section.extend_from_slice(bytecode);

    let mut blob_index: Vec<u8> = Vec::new();
    let mut count: u8 = 0;
    let push = |index: &mut Vec<u8>, c: &mut u8, field: u8, len: usize| {
        index.push(BLOB_START_OF_ENTRY);
        index.push(BLOB_RESOURCE_FIELD_TYPE);
        index.push(field);
        index.push(BLOB_RAW_PAYLOAD_LENGTH);
        index.extend_from_slice(&(len as u64).to_le_bytes());
        index.push(BLOB_INTERIOR_PADDING);
        index.push(PADDING_NONE);
        index.push(BLOB_END_OF_ENTRY);
        *c += 1;
    };
    push(&mut blob_index, &mut count, RES_NAME, name_section.len());
    push(
        &mut blob_index,
        &mut count,
        RES_IN_MEMORY_BYTECODE,
        bytecode_section.len(),
    );
    blob_index.push(BLOB_END_OF_INDEX);

    let mut resources_index: Vec<u8> = Vec::new();
    resources_index.push(RES_START_OF_ENTRY);
    resources_index.push(RES_NAME);
    resources_index.extend_from_slice(&(name.len() as u16).to_le_bytes());
    resources_index.push(RES_IS_PYTHON_MODULE);
    resources_index.push(RES_IN_MEMORY_BYTECODE);
    resources_index.extend_from_slice(&(bytecode.len() as u32).to_le_bytes());
    resources_index.push(RES_END_OF_ENTRY);
    resources_index.push(RES_END_OF_INDEX);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"pyembed\x03");
    out.push(count);
    out.extend_from_slice(&(blob_index.len() as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(resources_index.len() as u32).to_le_bytes());
    out.extend_from_slice(&blob_index);
    out.extend_from_slice(&resources_index);
    out.extend_from_slice(&name_section);
    out.extend_from_slice(&bytecode_section);
    out.extend_from_slice(b"python314.dll\0pyoxidizer_run\0python-stdlib");
    out
}

fn fixture(rel: &str) -> Option<Vec<u8>> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
        .join("freezers")
        .join(rel);
    std::fs::read(&path).ok()
}

const MAX_INPUT_LEN: usize = 4096;

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let capped: &[u8] = &seed[..seed.len().min(MAX_INPUT_LEN)];
    let mut out: Vec<u8> = capped.to_vec();
    match rng.next_u64() % 6 {
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
            let count: usize = rng.next_usize(32);
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
            let extra: usize = rng.next_usize(64);
            for _ in 0..extra {
                if out.len() >= MAX_INPUT_LEN {
                    break;
                }
                out.push(rng.next_byte());
            }
        }
        _ => {
            let len: usize = rng.next_usize(512);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    out
}

#[test]
fn pure_random_inputs_never_panic() {
    silence_panics();
    let mut rng: Xorshift64 = Xorshift64::new(0x5046_5A17_0001_0002);
    for _ in 0..6_000 {
        let len: usize = rng.next_usize(512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let mut local: Xorshift64 = Xorshift64::new(rng.next_u64());
        exercise(&bytes, &mut local);
    }
}

#[test]
fn mutated_synthetic_seeds_never_panic() {
    silence_panics();
    let seeds: [Vec<u8>; 5] = [
        pyc_seed(),
        py2exe_scriptinfo_seed(),
        minimal_pe_seed(),
        pyoxidizer_v3_seed(),
        Vec::new(),
    ];
    let mut rng: Xorshift64 = Xorshift64::new(0x5046_9099_0304_0506);
    for seed in &seeds {
        for _ in 0..4_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            let mut local: Xorshift64 = Xorshift64::new(rng.next_u64());
            exercise(&mutated, &mut local);
        }
    }
}

#[test]
fn mutated_real_fixtures_never_panic() {
    silence_panics();
    let rels: [&str; 4] = [
        "cxfreeze/hello.exe",
        "py2exe/hello.exe",
        "pex/hello.pex",
        "shiv/hello.pyz",
    ];
    let mut rng: Xorshift64 = Xorshift64::new(0x5046_C0DE_0708_090A);
    let mut exercised_any: bool = false;
    for rel in rels {
        let Some(seed): Option<Vec<u8>> = fixture(rel) else {
            eprintln!("SKIP: freezer fixture missing at {rel}");
            continue;
        };
        exercised_any = true;
        for _ in 0..2_000 {
            let mutated: Vec<u8> = mutate(&seed, &mut rng);
            let mut local: Xorshift64 = Xorshift64::new(rng.next_u64());
            exercise(&mutated, &mut local);
        }
    }
    if !exercised_any {
        eprintln!(
            "SKIP: no real freezer fixtures available; synthetic seeds still cover the surface"
        );
    }
}
