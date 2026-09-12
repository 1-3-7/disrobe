#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::items_after_statements
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

use disrobe_pass_wasm_deob::{
    analyze_module, count_defined_function_bodies, detect, extract_signatures,
    lift_module_faithful_wat, recover_gc_types, recover_module, scan_custom_page_sizes,
    scan_function_refs, scan_gc_extern, scan_js_string_builtins, scan_memories, scan_module_eh,
    scan_simd, scan_threads,
};

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
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

    const fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
}

const WASM_MAGIC: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
const MAX_INPUT: usize = 8192;

const ARITH4: &[u8] = include_bytes!("fixtures/arith4.wasm");
const NAME_OBF_CLEAN: &[u8] = include_bytes!("fixtures/wasm_name_obf_clean.wasm");

const WAT_SEEDS: &[&str] = &[
    "(module (func (export \"a\") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))",
    "(module (func (export \"b\") (param i32) (result i32) (local i32) block local.get 0 i32.eqz \
     br_if 0 loop local.get 0 i32.const 1 i32.sub local.set 0 local.get 0 br_if 0 end end \
     local.get 0))",
    "(module (memory 1) (func (export \"c\") (param i32) (result i32) local.get 0 i32.load \
     local.get 0 i32.const 4 i32.add i32.load i32.add))",
    "(module (func (export \"d\") (param i32) (result i32) local.get 0 i32.const 3 i32.const 5 \
     i32.const 7 br_table 0 1 2 drop drop i32.const 0 return))",
    "(module (global (mut i32) (i32.const 0)) (func (export \"e\") (result i32) global.get 0 \
     i32.const 1 i32.add global.set 0 global.get 0))",
    "(module (func $rec (export \"f\") (param i32) (result i32) local.get 0 i32.eqz if (result i32) \
     i32.const 1 else local.get 0 local.get 0 i32.const 1 i32.sub call $rec i32.mul end))",
];

fn silence_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| std::panic::set_hook(Box::new(|_| {})));
}

fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![ARITH4.to_vec(), NAME_OBF_CLEAN.to_vec()];
    for text in WAT_SEEDS {
        if let Ok(bytes) = wat::parse_str(text) {
            out.push(bytes);
        }
    }
    out
}

fn exercise(bytes: &[u8]) {
    let _ = detect(bytes);
    let _ = analyze_module(bytes);
    let _ = recover_module(bytes);
    let _ = lift_module_faithful_wat(bytes);
    let _ = extract_signatures(bytes);
    let _ = count_defined_function_bodies(bytes);
    let _ = recover_gc_types(bytes);
    let _ = scan_simd(bytes);
    let _ = scan_threads(bytes);
    let _ = scan_function_refs(bytes);
    let _ = scan_gc_extern(bytes);
    let _ = scan_memories(bytes);
    let _ = scan_custom_page_sizes(bytes);
    let _ = scan_js_string_builtins(bytes);
    let _ = scan_module_eh(bytes);
}

fn drive(bytes: &[u8]) {
    let owned: Vec<u8> = bytes.to_vec();
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| exercise(&owned)));
    if result.is_err() {
        eprintln!("FUZZFAIL len={} bytes={:02x?}", bytes.len(), bytes);
    }
    assert!(
        result.is_ok(),
        "wasm decode unwound on fuzz input ({} bytes): {:02x?}",
        bytes.len(),
        &bytes[..bytes.len().min(64)]
    );
}

fn mutate(rng: &mut XorShift64, seed: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = seed.to_vec();
    match rng.next_usize(6) {
        0 => {
            if !buf.is_empty() {
                let cut: usize = rng.next_usize(buf.len());
                buf.truncate(cut);
            }
        }
        1 => {
            let flips: usize = 1 + rng.next_usize(12);
            for _ in 0..flips {
                if buf.is_empty() {
                    break;
                }
                let idx: usize = rng.next_usize(buf.len());
                buf[idx] ^= 1u8 << rng.next_usize(8);
            }
        }
        2 => {
            let sets: usize = 1 + rng.next_usize(12);
            for _ in 0..sets {
                if buf.is_empty() {
                    break;
                }
                let idx: usize = rng.next_usize(buf.len());
                buf[idx] = rng.byte();
            }
        }
        3 => {
            let extra: usize = rng.next_usize(MAX_INPUT.saturating_sub(buf.len()).max(1));
            for _ in 0..extra {
                buf.push(rng.byte());
            }
        }
        4 => {
            if buf.len() >= 5 {
                let idx: usize = rng.next_usize(buf.len() - 4);
                for off in 0..5usize {
                    buf[idx + off] = rng.byte();
                }
            }
        }
        _ => {
            let idx: usize = if buf.is_empty() {
                0
            } else {
                rng.next_usize(buf.len())
            };
            let count: usize = rng.next_usize(48);
            for _ in 0..count {
                buf.insert(idx.min(buf.len()), rng.byte());
            }
        }
    }
    buf.truncate(MAX_INPUT);
    buf
}

#[test]
fn seed_mutations_never_panic() {
    silence_panic_hook();
    let pool: Vec<Vec<u8>> = seeds();
    assert!(
        pool.len() >= 2,
        "at least the wasm fixtures must seed the fuzz"
    );
    for seed in &pool {
        drive(seed);
    }
    let mut rng: XorShift64 = XorShift64::new(0x00C0_FFEE_D15E_A5E5);
    for _ in 0..6_000 {
        let seed: &[u8] = &pool[rng.next_usize(pool.len())];
        let mutated: Vec<u8> = mutate(&mut rng, seed);
        drive(&mutated);
    }
}

#[test]
fn pure_random_inputs_never_panic() {
    silence_panic_hook();
    let mut rng: XorShift64 = XorShift64::new(0xDEAD_BEEF_1337_4242);
    for _ in 0..4_000 {
        let len: usize = rng.next_usize(512);
        let mut buf: Vec<u8> = Vec::with_capacity(len + 8);
        if rng.next_u64() & 1 == 0 {
            buf.extend_from_slice(&WASM_MAGIC);
        }
        for _ in 0..len {
            buf.push(rng.byte());
        }
        drive(&buf);
    }
}
