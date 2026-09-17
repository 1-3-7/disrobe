#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::items_after_statements
)]

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use disrobe_py_marshal::PyVersion as MarshalVersion;
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PycFile, PycHeader, write_pyc};

use disrobe_pass_py_decompile::decompile_pyc;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};

fn opcode_for(name: &str, version: MarshalVersion) -> u8 {
    (0u16..=u16::from(u8::MAX))
        .map(|raw: u16| raw as u8)
        .find(|&raw: &u8| disrobe_pass_py_disasm::opname(raw, version) == name)
        .unwrap_or_else(|| panic!("opcode {name} not found for {version:?}"))
}

fn adversarial_code() -> CodeObject {
    const MARSHAL: MarshalVersion = MarshalVersion::PY312;
    let extended_arg: u8 = opcode_for("EXTENDED_ARG", MARSHAL);
    let jump_forward: u8 = opcode_for("JUMP_FORWARD", MARSHAL);
    let return_value: u8 = opcode_for("RETURN_VALUE", MARSHAL);

    let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    code.consts = vec![Object::None];
    code.name = Object::String {
        value: "adversarial".to_owned(),
        interned: false,
    };
    code.qualname = code.name.clone();
    code.filename = Object::String {
        value: "<adversarial>".to_owned(),
        interned: false,
    };
    code.stacksize = 8;
    code.code = vec![
        extended_arg,
        0xFF,
        extended_arg,
        0xFF,
        extended_arg,
        0xFF,
        jump_forward,
        0xFF,
        return_value,
        0,
    ];
    code
}

#[test]
fn extended_arg_jump_past_end_never_unwinds_through_pyc_api() {
    let code: CodeObject = adversarial_code();
    let header: PycHeader =
        PycHeader::deterministic(MarshalVersion::PY312).expect("deterministic 3.12 header");
    let pyc: PycFile = PycFile {
        header,
        code: Object::Code(Box::new(code)),
    };
    let bytes: Vec<u8> = write_pyc(&pyc).expect("marshal adversarial pyc");

    let (tx, rx): (mpsc::Sender<bool>, mpsc::Receiver<bool>) = mpsc::channel();
    let worker: thread::JoinHandle<()> = thread::Builder::new()
        .name("pyc-jump-past-end".to_owned())
        .stack_size(4 * 1024 * 1024)
        .spawn(move || {
            let outcome: bool = decompile_pyc(&bytes).is_ok();
            let _ = tx.send(outcome);
        })
        .expect("spawn worker");

    let _completed: bool = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("decompile_pyc must terminate without hanging on adversarial bytecode");
    worker
        .join()
        .expect("decompile_pyc must not unwind on adversarial bytecode");
}

#[test]
fn extended_arg_jump_past_end_core_returns_total_result() {
    let code: CodeObject = adversarial_code();
    let decompile_version: disrobe_pass_py_decompile::bytecode::version::PyVersion =
        marshal_to_decompile(MarshalVersion::PY312).expect("version map");

    let (tx, rx): (mpsc::Sender<bool>, mpsc::Receiver<bool>) = mpsc::channel();
    let worker: thread::JoinHandle<()> = thread::Builder::new()
        .name("core-jump-past-end".to_owned())
        .stack_size(4 * 1024 * 1024)
        .spawn(move || {
            let ok: bool =
                build_real_source(&code, &decompile_version, MarshalVersion::PY312).is_ok();
            let _ = tx.send(ok);
        })
        .expect("spawn worker");

    let recovered_ok: bool = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("build_real_source must terminate on adversarial bytecode");
    worker
        .join()
        .expect("build_real_source must not unwind on adversarial bytecode");
    assert!(
        recovered_ok,
        "an unresolvable extended-arg jump must degrade to best-effort Ok"
    );
}
