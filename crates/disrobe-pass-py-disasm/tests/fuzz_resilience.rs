#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
use disrobe_pass_py_disasm::alt_runtimes::micropython::{parse as mpy_parse, parse_bytecode};
use disrobe_pass_py_disasm::alt_runtimes::micropython_native::parse as native_parse;
use disrobe_pass_py_disasm::alt_runtimes::pypy::parse as pypy_parse;
use disrobe_pass_py_disasm::alt_runtimes::recover::{recover, recover_detected};
use disrobe_pass_py_disasm::alt_runtimes::{AltRuntime, detect_runtime};
#[cfg(feature = "chain")]
use disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS;

const MAX_INPUT_SIZE: usize = 4096;

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

    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

const SEEDS: &[&[u8]] = &[
    include_bytes!("../../../corpus/python/decompile/legacy/compiled/simple_const.3.11.pyc"),
    include_bytes!("../../../corpus/python/decompile/legacy/compiled/simple_const.3.12.pyc"),
    include_bytes!("../../../corpus/python/decompile/legacy/compiled/build_const_key_map.2.7.pyc"),
    include_bytes!("../../../corpus/python/decompile/legacy/compiled/binary_ops.3.11.pyc"),
    include_bytes!("../../../corpus/python/alt_runtimes/pypy/methods.pypy27.pyc"),
    include_bytes!("../../../corpus/python/alt_runtimes/pypy/hello_pypy39_legacy.pypy39.pyc"),
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy"),
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/control_flow.mpy"),
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_x64.mpy"),
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_armv7m.mpy"),
];

fn exercise(bytes: &[u8]) {
    let detected: Option<AltRuntime> = detect_runtime(bytes);
    let _ = detected;
    let _ = recover_detected(bytes);
    for runtime in [
        AltRuntime::PyPy,
        AltRuntime::MicroPython,
        AltRuntime::MicroPythonNative,
        AltRuntime::Jython,
        AltRuntime::IronPython,
        AltRuntime::Brython,
    ] {
        let _ = recover(bytes, runtime);
    }
    let _ = mpy_parse(bytes);
    let _ = parse_bytecode(bytes);
    let _ = native_parse(bytes);
    if let Ok(module) = pypy_parse(bytes) {
        let _ = module.disassemble();
    }
    run_pass(bytes);
}

#[cfg(feature = "chain")]
fn run_pass(bytes: &[u8]) {
    let input: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let _ = PY_DISASM_PASS.run(&input);
}

#[cfg(not(feature = "chain"))]
const fn run_pass(_bytes: &[u8]) {}

fn mutate(rng: &mut XorShift64, seed: &[u8]) -> Vec<u8> {
    let initial_len: usize = seed.len().min(MAX_INPUT_SIZE);
    let mut buf: Vec<u8> = seed[..initial_len].to_vec();
    match rng.next_usize(6) {
        0 => {
            if !buf.is_empty() {
                let truncate_to: usize = rng.next_usize(buf.len());
                buf.truncate(truncate_to);
            }
        }
        1 => {
            let flips: usize = 1 + rng.next_usize(8);
            for _ in 0..flips {
                if buf.is_empty() {
                    break;
                }
                let idx: usize = rng.next_usize(buf.len());
                if let Some(slot) = buf.get_mut(idx) {
                    *slot ^= 1u8 << (rng.next_usize(8));
                }
            }
        }
        2 => {
            let sets: usize = 1 + rng.next_usize(8);
            for _ in 0..sets {
                if buf.is_empty() {
                    break;
                }
                let idx: usize = rng.next_usize(buf.len());
                if let Some(slot) = buf.get_mut(idx) {
                    *slot = rng.next_byte();
                }
            }
        }
        3 => {
            let extra: usize = rng.next_usize(MAX_INPUT_SIZE.saturating_sub(buf.len()).max(1));
            for _ in 0..extra {
                buf.push(rng.next_byte());
            }
        }
        4 => {
            let want: usize = 1 + rng.next_usize(4);
            let original: Vec<u8> = buf.clone();
            for _ in 1..want {
                if buf.len() + original.len() > MAX_INPUT_SIZE {
                    break;
                }
                buf.extend_from_slice(&original);
            }
        }
        _ => {
            if buf.len() >= 4 {
                let idx: usize = rng.next_usize(buf.len() - 3);
                for offset in 0..4usize {
                    if let Some(slot) = buf.get_mut(idx + offset) {
                        *slot = rng.next_byte();
                    }
                }
            }
        }
    }
    buf.truncate(MAX_INPUT_SIZE);
    buf
}

#[test]
fn seed_mutations_never_panic_across_entry_points() {
    let mut rng: XorShift64 = XorShift64::new(0x5DEE_CE66_D33D_0001);
    for seed in SEEDS {
        let bounded_len: usize = seed.len().min(MAX_INPUT_SIZE);
        exercise(&seed[..bounded_len]);
    }
    for _ in 0..6_000 {
        let seed: &[u8] = SEEDS[rng.next_usize(SEEDS.len())];
        let mutated: Vec<u8> = mutate(&mut rng, seed);
        exercise(&mutated);
    }
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x9DD1_5A81_9DD1_0001);
    for _ in 0..20_000 {
        let len: usize = rng.next_usize(512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}
