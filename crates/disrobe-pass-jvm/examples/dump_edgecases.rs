#![allow(clippy::expect_used, clippy::panic, clippy::many_single_char_names)]

use std::fs;
use std::io::Read as _;
use std::path::PathBuf;

use disrobe_pass_jvm::{DecompiledClass, decompile_class, parse_classfile};

fn main() {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus/jvm/megafile/EdgeCases-baseline.jar");
    let f: fs::File = fs::File::open(&p).expect("open jar");
    let mut z: zip::ZipArchive<fs::File> = zip::ZipArchive::new(f).expect("zip");
    let target: String = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "EdgeCases.class".to_string());
    for i in 0..z.len() {
        let mut e: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if e.name() != target {
            continue;
        }
        let mut b: Vec<u8> = Vec::new();
        e.read_to_end(&mut b).expect("read");
        let cf = parse_classfile(&b).expect("parse");
        let d: DecompiledClass = decompile_class(&cf);
        println!("{}", d.source);
        return;
    }
    eprintln!("class {target} not found");
}
