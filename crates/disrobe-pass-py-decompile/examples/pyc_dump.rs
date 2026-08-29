#![allow(clippy::expect_used, clippy::print_stdout, clippy::print_stderr)]
use std::fs;

use disrobe_pass_py_decompile::decompile_pyc;

fn main() {
    let path: String = std::env::args().nth(1).expect("usage: dump <pyc>");
    let bytes: Vec<u8> = fs::read(&path).expect("read pyc");
    let out: disrobe_pass_py_decompile::NativeDecompile = decompile_pyc(&bytes).expect("decompile");
    eprintln!(
        "recovered_directly={} fallback={:?}",
        out.recovered_directly, out.fallback_reason
    );
    println!("{}", out.source);
    if std::env::var("DUMP_DIS").is_ok() {
        let mv: disrobe_py_marshal::PyVersion = out.marshal_version;
        let ins: Vec<disrobe_pass_py_disasm::Instruction> =
            disrobe_pass_py_disasm::disassemble(&out.code, mv);
        eprintln!("{}", disrobe_pass_py_disasm::render_dis(&ins));
    }
}
