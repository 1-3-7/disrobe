#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::panic
)]
use std::path::PathBuf;

use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path: PathBuf = PathBuf::from(args.get(1).expect("usage: decomp_pyc <path.pyc>"));
    let bytes: Vec<u8> = std::fs::read(&path).expect("read pyc");
    let pyc: PycFile = read_pyc(&bytes).expect("read_pyc");
    let mv: MarshalVersion = pyc.header.version;
    let code: CodeObject = match pyc.code {
        Object::Code(b) => *b,
        _ => panic!("not code"),
    };
    let dv = marshal_to_decompile(mv).expect("ver");
    match build_real_source(&code, &dv, mv) {
        Ok(s) => println!("{s}"),
        Err(e) => println!("ERROR: {e}"),
    }
}
