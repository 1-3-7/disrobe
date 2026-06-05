#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::fs;
use std::io::Read as _;
use std::path::PathBuf;

use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes, parse_classfile};

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

fn load_fixture(path: &PathBuf) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

fn classes_from_jar(jar_path: &PathBuf) -> Option<Vec<(String, Vec<u8>)>> {
    let f: fs::File = fs::File::open(jar_path).ok()?;
    let mut z: zip::ZipArchive<fs::File> = zip::ZipArchive::new(f).expect("zip read");
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if entry.name().ends_with(".class") {
            let name: String = entry.name().to_string();
            let prealloc: usize = (entry.size() as usize).min(8 * 1024 * 1024);
            let mut bytes: Vec<u8> = Vec::with_capacity(prealloc);
            entry.read_to_end(&mut bytes).expect("read class");
            out.push((name, bytes));
        }
    }
    Some(out)
}

#[test]
fn hello_class_is_structured_not_goto_labels() {
    let path: PathBuf = corpus(&["proguard", "Hello-baseline.class"]);
    let Some(bytes): Option<Vec<u8>> = load_fixture(&path) else {
        eprintln!(
            "skip: Hello-baseline.class fixture absent at {}",
            path.display()
        );
        return;
    };
    let d: DecompiledClass = decompile_classfile_bytes(&bytes).expect("decompile");
    let src: &str = &d.source;
    assert!(
        !src.contains("goto L") && !src.contains("// goto L"),
        "decompiled source still contains raw goto labels:\n{src}"
    );
    assert!(
        !src.contains("if (") || src.contains(") {"),
        "if statements must use block braces not labels:\n{src}"
    );
    assert!(
        src.contains("if (") && src.contains("} else {"),
        "Hello.describe should reconstruct as if/else:\n{src}"
    );
}

#[test]
fn baseline_jar_recovers_real_control_flow_keywords() {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!(
            "skip: EdgeCases-baseline.jar fixture absent at {}",
            jar.display()
        );
        return;
    };
    let mut whole: String = String::new();
    for (_name, bytes) in &classes {
        let cf = parse_classfile(bytes).expect("parse");
        let d: DecompiledClass = disrobe_pass_jvm::decompile_class(&cf);
        whole.push_str(&d.source);
        whole.push('\n');
    }
    assert!(
        whole.contains("if (") && whole.contains("} else {"),
        "baseline jar must recover if/else somewhere"
    );
    assert!(
        whole.contains("while ("),
        "baseline jar must recover while-loop somewhere"
    );
    assert!(
        whole.contains("switch ("),
        "baseline jar must recover switch somewhere"
    );
    let raw_goto_count: usize = whole.matches("goto L").count();
    assert!(
        raw_goto_count == 0
            || whole.contains("/// irreducible CFG")
            || whole.contains("/// irreducible region"),
        "{raw_goto_count} unstructured goto labels remain without irreducible marker"
    );
}

#[test]
fn mutation_proof_if_else_keyword_required() {
    let path: PathBuf = corpus(&["proguard", "Hello-baseline.class"]);
    let Some(bytes): Option<Vec<u8>> = load_fixture(&path) else {
        eprintln!(
            "skip: Hello-baseline.class fixture absent at {}",
            path.display()
        );
        return;
    };
    let d: DecompiledClass = decompile_classfile_bytes(&bytes).expect("decompile");
    let needle: &str = "} else {";
    let count: usize = d.source.matches(needle).count();
    assert!(
        count >= 1,
        "expected at least one '{needle}' in Hello source"
    );
}
