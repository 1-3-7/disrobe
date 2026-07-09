#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
use disrobe_pass_py_disasm::alt_runtimes::{
    AltRuntime, micropython, micropython_native, pypy, recover,
};
#[cfg(feature = "chain")]
use disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS;
use disrobe_pass_py_disasm::{
    Cfg, build_cfg, decode_exception_table, detect_runtime, disassemble, format_identity,
    format_python, jump_target_fitness, render_dis, render_dot, render_listing,
};
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

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

const VERSIONS: [PyVersion; 8] = [
    PyVersion::PY27,
    PyVersion::PY37,
    PyVersion::PY38,
    PyVersion::PY311,
    PyVersion::PY312,
    PyVersion::PY313,
    PyVersion::PY314,
    PyVersion::PY315,
];

const ERAS: [CodeEra; 3] = [CodeEra::Py27, CodeEra::Py38to310, CodeEra::Py311Plus];

fn synth_object(rng: &mut XorShift64, depth: usize) -> Object {
    match rng.range(0, 7) {
        0 => Object::None,
        1 => Object::Int(rng.next_u64() as i32),
        2 => Object::String {
            value: "s".to_owned(),
            interned: false,
        },
        3 => Object::ShortAscii {
            value: "a".to_owned(),
            interned: false,
        },
        4 => Object::Bytes(vec![rng.byte(), rng.byte()]),
        5 if depth < 2 => Object::Tuple(vec![Object::None, Object::Int(rng.next_u64() as i32)]),
        _ if depth < 1 => {
            let mut inner: CodeObject = CodeObject::new(CodeEra::Py311Plus);
            inner.code = vec![rng.byte(), rng.byte(), rng.byte(), rng.byte()];
            Object::Code(Box::new(inner))
        }
        _ => Object::Int(rng.next_u64() as i32),
    }
}

fn synth_objects(rng: &mut XorShift64, n: usize) -> Vec<Object> {
    (0..n).map(|_| synth_object(rng, 0)).collect()
}

fn synth_code(rng: &mut XorShift64, era: CodeEra) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(era);
    let code_len: usize = rng.range(0, 400);
    co.code = (0..code_len).map(|_| rng.byte()).collect();
    let n_consts: usize = rng.range(0, 8);
    co.consts = synth_objects(rng, n_consts);
    let n_names: usize = rng.range(0, 6);
    co.names = synth_objects(rng, n_names);
    let n_varnames: usize = rng.range(0, 6);
    co.varnames = synth_objects(rng, n_varnames);
    let n_lpn: usize = rng.range(0, 6);
    co.localsplusnames = synth_objects(rng, n_lpn);
    let n_free: usize = rng.range(0, 3);
    co.freevars = synth_objects(rng, n_free);
    let n_cell: usize = rng.range(0, 3);
    co.cellvars = synth_objects(rng, n_cell);
    let et_len: usize = rng.range(0, 64);
    co.exceptiontable = (0..et_len).map(|_| rng.byte()).collect();
    let lnotab_len: usize = rng.range(0, 64);
    co.lnotab = (0..lnotab_len).map(|_| rng.byte()).collect();
    let lt_len: usize = rng.range(0, 64);
    co.linetable = (0..lt_len).map(|_| rng.byte()).collect();
    co.firstlineno = rng.next_u64() as i32;
    co.name = Object::ShortAscii {
        value: "f".to_owned(),
        interned: false,
    };
    co
}

fn drive_code(co: &CodeObject, version: PyVersion, desc: &str) {
    guard("disassemble", desc, || {
        let _ = disassemble(co, version);
    });
    guard("jump_target_fitness", desc, || {
        let _ = jump_target_fitness(co, version);
    });
    guard("render_dis+render_listing", desc, || {
        let instrs: Vec<_> = disassemble(co, version);
        let _ = render_dis(&instrs);
        let _ = render_listing(&instrs, co, version);
    });
    guard("build_cfg+render_dot", desc, || {
        let instrs: Vec<_> = disassemble(co, version);
        let cfg: Cfg = build_cfg(&instrs, version);
        let _ = render_dot(&cfg);
    });
    guard("decode_exception_table(co)", desc, || {
        let _ = decode_exception_table(&co.exceptiontable);
    });
}

fn drive_bytes(bytes: &[u8], desc: &str) {
    guard("decode_exception_table", desc, || {
        let _ = decode_exception_table(bytes);
    });
    #[cfg(feature = "chain")]
    guard("chain_detector::PY_DISASM_PASS::run", desc, || {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
        let _ = PY_DISASM_PASS.run(&artifact);
    });
    guard("detect_runtime", desc, || {
        let _ = detect_runtime(bytes);
    });
    guard("micropython::detect+parse", desc, || {
        let _ = micropython::detect(bytes);
        let _ = micropython::parse(bytes);
        if let Ok(module) = micropython::parse_bytecode(bytes) {
            let _ = micropython::render(&module);
        }
    });
    guard("micropython_native::detect+parse", desc, || {
        let _ = micropython_native::detect(bytes);
        let _ = micropython_native::parse(bytes);
    });
    guard("pypy::detect+parse", desc, || {
        let _ = pypy::detect(bytes);
        let _ = pypy::parse(bytes);
    });
    guard("recover", desc, || {
        for rt in [
            AltRuntime::PyPy,
            AltRuntime::MicroPython,
            AltRuntime::MicroPythonNative,
            AltRuntime::Jython,
            AltRuntime::IronPython,
            AltRuntime::Brython,
        ] {
            let _ = recover::recover(bytes, rt);
        }
        let _ = recover::recover_detected(bytes);
    });
    guard("format_python+format_identity", desc, || {
        let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
        let _ = format_python(&text);
        let _ = format_identity(&text);
    });
}

fn corpus() -> Vec<Vec<u8>> {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("../../corpus/python");
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "pyc") {
                if let Ok(bytes) = std::fs::read(&path) {
                    out.push(bytes);
                }
                if out.len() >= 24 {
                    return out;
                }
            }
        }
    }
    out
}

fn byte_seeds() -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = vec![
        vec![0x6F, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0xCB, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![b'M', 0x06, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00],
        vec![b'P', b'Y', b'P', b'Y', 0x00, 0x00, 0x00, 0x00],
        (0..96u8).collect(),
        vec![0x00, 0x0A, 0x00, 0x00, 0x64, 0x00, 0x00, 0x53, 0x00],
    ];
    seeds.extend(corpus());
    seeds
}

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
fn synthetic_code_objects_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x00C0_FFEE_D15E_A5E5);
    const ITERATIONS: usize = 6000;
    for i in 0..ITERATIONS {
        let era: CodeEra = ERAS[i % ERAS.len()];
        let co: CodeObject = synth_code(&mut rng, era);
        let version: PyVersion = VERSIONS[rng.range(0, VERSIONS.len() - 1)];
        drive_code(&co, version, "synthetic-code");
    }
}

#[test]
fn byte_seeded_mutations_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0xDEAD_BEEF_1337_4242);
    let seeds: Vec<Vec<u8>> = byte_seeds();
    const ITERATIONS: usize = 3000;
    for i in 0..ITERATIONS {
        let base: &Vec<u8> = &seeds[i % seeds.len()];
        let mutated: Vec<u8> = mutate(&mut rng, base);
        drive_bytes(&mutated, "byte-seeded-mutation");
    }
}

#[test]
fn byte_random_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x5EED_C0DE_F00D_BA11);
    const ITERATIONS: usize = 4000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_bytes(&bytes, "byte-random");
    }
}
