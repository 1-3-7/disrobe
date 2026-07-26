#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_pickle::chain_detector::PICKLE_PASS;
use disrobe_pass_pickle::vm::PickleValue;
use disrobe_pass_pickle::{
    AnalysisOptions, Disassembly, Policy, VmTrace, analyze_all, analyze_deep, analyze_polyglot,
    analyze_safety, analyze_with_options, analyze_with_policy, disassemble, execute, execute_full,
    looks_like_pickle, reconstruct, render_disasm, to_python, to_python_assignment,
};

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize) % (hi - lo + 1)
    }
}

fn guard<F: FnOnce()>(label: &str, desc: &str, f: F) {
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(f));
    assert!(result.is_ok(), "{label} unwound on fuzz input ({desc})");
}

#[cfg(feature = "ml")]
fn drive_ml(bytes: &[u8], desc: &str) {
    use disrobe_pass_pickle::{detect_model, extract_ml};
    guard("detect_model", desc, || {
        let _ = detect_model(bytes);
    });
    guard("extract_ml", desc, || {
        let _ = extract_ml(bytes);
    });
}

#[cfg(not(feature = "ml"))]
fn drive_ml(_bytes: &[u8], _desc: &str) {}

fn drive_bytes(bytes: &[u8], desc: &str) {
    guard("looks_like_pickle", desc, || {
        let _ = looks_like_pickle(bytes);
    });
    guard("analyze_polyglot", desc, || {
        let _ = analyze_polyglot(bytes);
    });
    guard("analyze_all", desc, || {
        let _ = analyze_all(bytes);
    });
    guard("PICKLE_PASS::run", desc, || {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
        let _ = PICKLE_PASS.run(&artifact);
    });
    guard("disassemble->everything", desc, || {
        let Ok(dis): Result<Disassembly, _> = disassemble(bytes) else {
            return;
        };
        let _ = render_disasm(&dis);
        let _ = execute(&dis);
        let Ok((trace, memo)): Result<(VmTrace, BTreeMap<u64, PickleValue>), _> =
            execute_full(&dis)
        else {
            return;
        };
        let _ = to_python(&trace.result);
        let _ = to_python_assignment(&trace.result);
        let _ = analyze_safety(&trace);
        let _ = analyze_deep(&trace);
        let _ = analyze_with_policy(&trace, &Policy::default());
        let _ = analyze_with_options(&trace, &AnalysisOptions::default());
        let _ = reconstruct(&trace.result, &memo, trace.root_memo_key);
    });
    drive_ml(bytes, desc);
}

const SEEDS: &[&[u8]] = &[
    b"\x80\x02K\x07.",
    b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01a\x94.",
    b"(lp0\nI1\naI2\na.",
    b"\x80\x05\x95\x00\x00\x00\x00\x00\x00\x00\x00}\x94.",
    b"]q\x00(K\x01K\x02K\x03e.",
    b"\x80\x03cbuiltins\nexec\nq\x00X\x04\x00\x00\x00pass\x85\x86.",
    b"\x80\x02}q\x00(U\x01aq\x01K\x01u.",
    b"c__main__\nfoo\n(t\x81.",
    b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94.",
    b"\x80\x02]q\x00h\x00a.",
    b"\x80\x02\x82\x10.",
    b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x8c\x06system\x93\x94.",
    b"PK\x03\x04",
    b"\x80\x05\x95\x08\x00\x00\x00\x00\x00\x00\x00(K\x01K\x02e\x94.",
];

fn mutate(rng: &mut XorShift64, base: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = base.to_vec();
    let rounds: usize = rng.range(1, 4);
    for _ in 0..rounds {
        match rng.range(0, 6) {
            0 => {
                if !buf.is_empty() {
                    let cut: usize = rng.range(0, buf.len());
                    buf.truncate(cut);
                }
            }
            1 => {
                if !buf.is_empty() {
                    let idx: usize = rng.range(0, buf.len() - 1);
                    buf[idx] ^= 1u8 << rng.range(0, 7);
                }
            }
            2 => {
                if !buf.is_empty() {
                    let idx: usize = rng.range(0, buf.len() - 1);
                    buf[idx] = rng.byte();
                }
            }
            3 => {
                let extra: usize = rng.range(1, 64);
                for _ in 0..extra {
                    buf.push(rng.byte());
                }
            }
            4 => {
                if buf.len() >= 2 {
                    let a: usize = rng.range(0, buf.len() - 1);
                    let b: usize = rng.range(0, buf.len() - 1);
                    buf.swap(a, b);
                }
            }
            _ => {
                let idx: usize = if buf.is_empty() {
                    0
                } else {
                    rng.range(0, buf.len())
                };
                buf.insert(idx.min(buf.len()), rng.byte());
            }
        }
    }
    buf
}

#[test]
fn seeded_mutations_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x00C0_FFEE_D15E_A5E5);
    const ITERATIONS: usize = 6000;
    for i in 0..ITERATIONS {
        let base: &[u8] = SEEDS[i % SEEDS.len()];
        let mutated: Vec<u8> = mutate(&mut rng, base);
        drive_bytes(&mutated, "seeded-mutation");
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x5EED_C0DE_F00D_BA11);
    const ITERATIONS: usize = 4000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_bytes(&bytes, "pure-random");
    }
}

#[test]
fn protocol_framed_opcode_storms_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x2545_F491_4F6C_DD1D);
    const ITERATIONS: usize = 6000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(2, 300);
        let mut bytes: Vec<u8> = Vec::with_capacity(len + 3);
        bytes.push(0x80);
        bytes.push((rng.byte() % 6) + 1);
        for _ in 0..len {
            bytes.push(rng.byte());
        }
        bytes.push(b'.');
        drive_bytes(&bytes, "opcode-storm");
    }
}
