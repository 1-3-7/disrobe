#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::map_unwrap_or,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::items_after_statements
)]
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    let out: std::process::Output = Command::new("uv")
        .args(["python", "find", alias])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p: PathBuf = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_owned());
    if p.is_file() { Some(p) } else { None }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let construct: &str = args.get(1).map(String::as_str).unwrap_or("class_simple");
    let alias: &str = args.get(2).map(String::as_str).unwrap_or("3.12");
    let src_path: PathBuf = PathBuf::from(format!(
        "../../corpus/python/decompile/construct/cases/{construct}.py"
    ));
    let interpreter: PathBuf = find_interpreter(alias).expect("interpreter");
    let scratch: PathBuf = std::env::temp_dir().join(format!("decomp_one_{construct}_{alias}.pyc"));
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let st: std::process::Output = Command::new(&interpreter)
        .args([
            "-c",
            script,
            src_path.to_str().unwrap(),
            scratch.to_str().unwrap(),
        ])
        .output()
        .expect("compile");
    if !st.status.success() {
        eprintln!("compile failed: {}", String::from_utf8_lossy(&st.stderr));
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&scratch).expect("read pyc");
    let pyc: PycFile = read_pyc(&bytes).expect("read_pyc");
    let mv: MarshalVersion = pyc.header.version;
    let code: CodeObject = match pyc.code {
        Object::Code(b) => *b,
        _ => panic!("not code"),
    };
    let dv = marshal_to_decompile(mv).expect("ver");
    println!("===== ORIGINAL SOURCE ({construct} @ {alias}) =====");
    println!("{}", std::fs::read_to_string(&src_path).unwrap());
    if std::env::var("DR_DUMP_OPS").is_ok() {
        use disrobe_pass_py_decompile::bytecode::opcode::map_for;
        let opmap = map_for(dv.clone());
        fn dump(
            co: &CodeObject,
            opmap: &dyn disrobe_pass_py_decompile::bytecode::opcode::OpcodeMap,
        ) {
            let bytes: &[u8] = &co.code;
            let name: String = match &co.name {
                Object::String { value, .. } | Object::ShortAscii { value, .. } => value.clone(),
                _ => "<?>".to_owned(),
            };
            println!("--- {name} ---");
            let mut cursor: usize = 0;
            let mut extended: u32 = 0;
            while cursor + 1 < bytes.len() {
                let raw: u8 = bytes[cursor];
                let arg_byte: u8 = bytes[cursor + 1];
                if raw == 144 {
                    extended = (extended | u32::from(arg_byte)) << 8;
                    cursor += 2;
                    continue;
                }
                let arg: u32 = extended | u32::from(arg_byte);
                extended = 0;
                let op = opmap.decode(raw, arg);
                println!("  {cursor:3}: raw={raw:3} arg={arg:3} -> {op:?}");
                cursor += 2;
                let caches: usize = usize::from(opmap.cache_size(raw));
                if caches > 0 {
                    cursor += caches * 2;
                }
            }
            for c in &co.consts {
                if let Object::Code(nested) = c {
                    dump(nested, opmap);
                }
            }
        }
        dump(&code, opmap.as_ref());
    }
    println!("===== DECOMPILED =====");
    match build_real_source(&code, &dv, mv) {
        Ok(s) => println!("{s}"),
        Err(e) => println!("ERROR: {e}"),
    }
}
