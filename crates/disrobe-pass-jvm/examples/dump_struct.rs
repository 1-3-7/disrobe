#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes};

fn main() {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus/jvm/proguard/Hello-baseline.class");
    let bytes: Vec<u8> = fs::read(&p).expect("read");
    let d: DecompiledClass = decompile_classfile_bytes(&bytes).expect("decomp");
    println!("{}", d.source);
}
