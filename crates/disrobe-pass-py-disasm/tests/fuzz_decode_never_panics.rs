use disrobe_pass_py_disasm::{
    Cfg, Instruction, build_cfg, cache_size, decode_exception_table, disassemble, has_arg,
    is_python_printable, jump_target_fitness, opname, render_dis, render_dot,
    render_exception_table, render_exception_table_json, render_listing,
};
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

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

    const fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    const fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize) % (hi - lo + 1)
    }
}

fn discard_result<T, E>(result: Result<T, E>) {
    match result {
        Ok(value) => {
            std::hint::black_box(value);
        }
        Err(error) => {
            std::hint::black_box(error);
        }
    }
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
const SYNTHETIC_ITERATIONS: usize = 6_000;
const BOUNDED_ITERATIONS: usize = 64;
const BOUNDED_RAW_BYTES: usize = 512;

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
    std::hint::black_box(desc);
    let instructions: Vec<Instruction> = disassemble(co, version);
    std::hint::black_box(jump_target_fitness(co, version));
    std::hint::black_box(render_dis(&instructions));
    std::hint::black_box(render_listing(&instructions, co, version));
    let cfg: Cfg = build_cfg(&instructions, version);
    std::hint::black_box(render_dot(&cfg));
    if let Ok(entries) = decode_exception_table(&co.exceptiontable) {
        std::hint::black_box(render_exception_table(&entries));
        discard_result(render_exception_table_json(&entries));
    }
}

fn drive_exception_table(bytes: &[u8]) {
    if let Ok(entries) = decode_exception_table(bytes) {
        std::hint::black_box(render_exception_table(&entries));
        discard_result(render_exception_table_json(&entries));
    }
}

fn drive_opcode_readers(version: PyVersion) {
    for opcode in u8::MIN..=u8::MAX {
        std::hint::black_box(opname(opcode, version));
        std::hint::black_box(has_arg(opcode, version));
        std::hint::black_box(cache_size(opcode, version));
    }
}

fn load_const_opcode(version: PyVersion) -> u8 {
    for opcode in u8::MIN..=u8::MAX {
        if opname(opcode, version) == "LOAD_CONST" {
            return opcode;
        }
    }
    0
}

fn force_const_render(co: &mut CodeObject, version: PyVersion) {
    let load_const: u8 = load_const_opcode(version);
    let mut code: Vec<u8> = if version.is_wordcode() {
        vec![load_const, 0]
    } else {
        vec![load_const, 0, 0]
    };
    code.extend_from_slice(&co.code);
    co.code = code;
    if co.consts.is_empty() {
        co.consts.push(Object::None);
    }
}

#[test]
fn synthetic_code_objects_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x00C0_FFEE_D15E_A5E5);
    for i in 0..SYNTHETIC_ITERATIONS {
        let era: CodeEra = ERAS[i % ERAS.len()];
        let co: CodeObject = synth_code(&mut rng, era);
        let version: PyVersion = VERSIONS[rng.range(0, VERSIONS.len() - 1)];
        drive_code(&co, version, "synthetic-code");
    }
}

#[test]
fn bounded_parse_inputs_complete_without_unwind_guards() {
    let mut rng: XorShift64 = XorShift64::new(0x0F0F_CE55_7EED_1235);
    for iteration in 0..BOUNDED_ITERATIONS {
        let version: PyVersion = VERSIONS[iteration % VERSIONS.len()];
        let era: CodeEra = ERAS[iteration % ERAS.len()];
        let mut co: CodeObject = synth_code(&mut rng, era);
        force_const_render(&mut co, version);
        let byte_count: usize = rng.range(0, BOUNDED_RAW_BYTES);
        let bytes: Vec<u8> = (0..byte_count).map(|_| rng.byte()).collect();
        drive_opcode_readers(version);
        drive_code(&co, version, "bounded-code-object");
        drive_exception_table(&bytes);
    }
    for ch in ['\0', '\n', ' ', '\u{00ad}', '\u{4e2d}', '\u{1f600}'] {
        std::hint::black_box(is_python_printable(ch));
    }
}

#[test]
fn high_continuation_exception_tables_return_errors() {
    for len in 1usize..=16 {
        let table: Vec<u8> = vec![u8::MAX; len];
        discard_result(decode_exception_table(&table));
    }
    let mixed: Vec<u8> = vec![u8::MAX; 8];
    discard_result(decode_exception_table(&mixed));
}

#[test]
fn maximum_cfg_offset_has_no_fallthrough_target() {
    let instructions: [Instruction; 1] = [Instruction {
        offset: usize::MAX,
        opcode: 110,
        opname: "JUMP_FORWARD".to_owned(),
        arg: Some(0),
        argrepr: None,
        line: None,
        is_jump_target: false,
    }];
    let cfg: Cfg = build_cfg(&instructions, PyVersion::PY312);
    assert!(cfg.blocks[0].successors.is_empty());
}

#[cfg(target_pointer_width = "32")]
#[test]
fn cfg_rejects_jump_distance_overflow() {
    let instructions: [Instruction; 3] = [
        Instruction {
            offset: 1,
            opcode: 110,
            opname: "JUMP_FORWARD".to_owned(),
            arg: Some(u32::MAX),
            argrepr: None,
            line: None,
            is_jump_target: false,
        },
        Instruction {
            offset: 0,
            opcode: 9,
            opname: "NOP".to_owned(),
            arg: None,
            argrepr: None,
            line: None,
            is_jump_target: false,
        },
        Instruction {
            offset: usize::MAX,
            opcode: 83,
            opname: "RETURN_VALUE".to_owned(),
            arg: None,
            argrepr: None,
            line: None,
            is_jump_target: false,
        },
    ];
    let cfg: Cfg = build_cfg(&instructions, PyVersion::PY312);
    let has_successor: bool = cfg
        .blocks
        .iter()
        .any(|block| block.start_offset == 1 && !block.successors.is_empty());
    assert!(!has_successor);
}
