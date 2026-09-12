#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::items_after_statements
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use disrobe_py_marshal::PyVersion as MarshalVersion;
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PycFile, read_pyc};

use disrobe_pass_py_decompile::decompile_pyc;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};

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

fn code_from_bytes(bytecode: Vec<u8>, era: CodeEra) -> CodeObject {
    let mut code: CodeObject = CodeObject::new(era);
    code.consts = vec![Object::None, Object::Int(0), Object::Int(1)];
    code.names = vec![Object::String {
        value: "n".to_owned(),
        interned: false,
    }];
    code.varnames = vec![Object::String {
        value: "v".to_owned(),
        interned: false,
    }];
    code.stacksize = 16;
    code.name = Object::String {
        value: "f".to_owned(),
        interned: false,
    };
    code.qualname = code.name.clone();
    code.filename = Object::String {
        value: "<fuzz>".to_owned(),
        interned: false,
    };
    code.code = bytecode;
    code
}

fn drive_core(code: CodeObject, marshal: MarshalVersion) {
    let Ok(decompile_version) = marshal_to_decompile(marshal) else {
        return;
    };
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
        let _ = build_real_source(&code, &decompile_version, marshal);
    }));
    assert!(
        result.is_ok(),
        "build_real_source unwound on fuzz input ({marshal:?}, {} bytes)",
        code.code.len()
    );
}

#[test]
fn random_bytecode_never_panics() {
    let mut rng: XorShift64 = XorShift64::new(0x00C0_FFEE_D15E_A5E5);
    const ITERATIONS: usize = 600;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(1, 128) * 2;
        let bytecode: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_core(
            code_from_bytes(bytecode.clone(), CodeEra::Py311Plus),
            MarshalVersion::PY312,
        );
        drive_core(
            code_from_bytes(bytecode.clone(), CodeEra::Py38to310),
            MarshalVersion::PY38,
        );
        drive_core(
            code_from_bytes(bytecode, CodeEra::Py27),
            MarshalVersion::PY27,
        );
    }
}

#[test]
fn structured_jump_bytecode_never_panics() {
    let mut rng: XorShift64 = XorShift64::new(0xDEAD_BEEF_1337_4242);
    let opcodes: [&str; 9] = [
        "EXTENDED_ARG",
        "JUMP_FORWARD",
        "JUMP_BACKWARD",
        "FOR_ITER",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_IF_TRUE",
        "LOAD_CONST",
        "STORE_FAST",
        "RETURN_VALUE",
    ];
    let raws: Vec<u8> = opcodes
        .iter()
        .map(|name: &&str| opcode_for(name, MarshalVersion::PY312))
        .collect();
    const ITERATIONS: usize = 400;
    for _ in 0..ITERATIONS {
        let ops: usize = rng.range(1, 96);
        let mut bytecode: Vec<u8> = Vec::with_capacity(ops * 2);
        for _ in 0..ops {
            let raw: u8 = raws[rng.range(0, raws.len() - 1)];
            bytecode.push(raw);
            bytecode.push(rng.byte());
        }
        drive_core(
            code_from_bytes(bytecode, CodeEra::Py311Plus),
            MarshalVersion::PY312,
        );
    }
}

fn opcode_for(name: &str, version: MarshalVersion) -> u8 {
    (0u16..=u16::from(u8::MAX))
        .map(|raw: u16| raw as u8)
        .find(|&raw: &u8| disrobe_pass_py_disasm::opname(raw, version) == name)
        .unwrap_or_else(|| panic!("opcode {name} not found for {version:?}"))
}

fn collect_corpus() -> Vec<PathBuf> {
    let root: PathBuf = PathBuf::from("../../corpus/python");
    let mut out: Vec<PathBuf> = Vec::new();
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
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn real_corpus_pipeline_never_panics() {
    let corpus: Vec<PathBuf> = collect_corpus();
    if corpus.is_empty() {
        return;
    }
    let mut checked: usize = 0;
    for path in &corpus {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let clean: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
            let _ = decompile_pyc(&bytes);
        }));
        assert!(
            clean.is_ok(),
            "decompile_pyc unwound on real corpus file {}",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "corpus present but nothing was exercised");
}

#[test]
fn corpus_seeded_bytecode_mutations_never_panic() {
    let corpus: Vec<PathBuf> = collect_corpus();
    if corpus.is_empty() {
        return;
    }
    let mut rng: XorShift64 = XorShift64::new(0x5EED_C0DE_F00D_BA11);
    let mut checked: usize = 0;
    for path in corpus.iter().take(200) {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(pyc): std::result::Result<PycFile, _> = read_pyc(&bytes) else {
            continue;
        };
        let Object::Code(boxed) = pyc.code else {
            continue;
        };
        let base: CodeObject = *boxed;
        let marshal: MarshalVersion = pyc.header.version;
        if marshal_to_decompile(marshal).is_err() {
            continue;
        }
        for _ in 0..8 {
            let mut code: CodeObject = base.clone();
            if !code.code.is_empty() {
                let flips: usize = rng.range(1, 16);
                for _ in 0..flips {
                    let idx: usize = rng.range(0, code.code.len() - 1);
                    code.code[idx] ^= rng.byte();
                }
            }
            drive_core(code, marshal);
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "corpus present but no code objects were exercised"
    );
}
