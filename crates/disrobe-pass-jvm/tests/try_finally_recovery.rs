#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::io::Read as _;
use std::path::PathBuf;

use disrobe_pass_jvm::{ClassFile, DecompiledClass, decompile_class, parse_classfile};

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    for part in parts {
        p.push(part);
    }
    p
}

fn edgecases_source() -> Option<String> {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let f: std::fs::File = std::fs::File::open(jar).ok()?;
    let mut z: zip::ZipArchive<std::fs::File> = zip::ZipArchive::new(f).ok()?;
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).ok()?;
        if entry.name() == "EdgeCases.class" {
            let mut bytes: Vec<u8> = Vec::new();
            entry.read_to_end(&mut bytes).ok()?;
            let cf: ClassFile = parse_classfile(&bytes).ok()?;
            let d: DecompiledClass = decompile_class(&cf);
            return Some(d.source);
        }
    }
    None
}

fn method_body(source: &str, signature_fragment: &str) -> Option<String> {
    let start: usize = source.find(signature_fragment)?;
    let open: usize = source[start..].find('{')? + start;
    let bytes: &[u8] = source.as_bytes();
    let mut depth: i32 = 0;
    let mut i: usize = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(source[open..=i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[test]
fn try_catch_finally_renders_a_real_finally_block() {
    let Some(source): Option<String> = edgecases_source() else {
        eprintln!("skip: EdgeCases baseline jar absent");
        return;
    };
    let body: String = method_body(&source, "divSafe(")
        .expect("divSafe method must be present in decompiled output");
    assert!(
        body.contains("} finally {"),
        "divSafe try-catch-finally must emit a real `finally` block; got:\n{body}"
    );
    assert!(
        body.contains("incrementAndGet"),
        "the finally body (CTR.incrementAndGet) must be recovered inside divSafe; got:\n{body}"
    );
}

#[test]
fn try_finally_renders_a_real_finally_block() {
    let Some(source): Option<String> = edgecases_source() else {
        eprintln!("skip: EdgeCases baseline jar absent");
        return;
    };
    let body: String =
        method_body(&source, " main(").expect("main method must be present in decompiled output");
    assert!(
        body.contains("} finally {"),
        "main's try-finally around the executor must emit a real `finally` block; got main body"
    );
    assert!(
        body.contains(".shutdown()"),
        "the finally body (exec.shutdown) must be recovered inside main"
    );
}

#[test]
fn no_handler_less_try_is_emitted_for_finally_constructs() {
    let Some(source): Option<String> = edgecases_source() else {
        eprintln!("skip: EdgeCases baseline jar absent");
        return;
    };
    for sig in ["divSafe(", " main("] {
        let Some(body): Option<String> = method_body(&source, sig) else {
            continue;
        };
        let bytes: &[u8] = body.as_bytes();
        let mut i: usize = 0;
        while let Some(rel) = body[i..].find("try {") {
            let try_at: usize = i + rel;
            let after: &str = body[try_at + "try {".len()..].trim_start();
            assert!(
                !after.starts_with('}'),
                "{sig} emitted a handler-less `try {{}}`; every try must carry a catch or finally; got:\n{body}"
            );
            i = try_at + "try {".len();
            let _ = bytes;
        }
    }
}
