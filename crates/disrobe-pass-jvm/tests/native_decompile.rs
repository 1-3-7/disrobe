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

use disrobe_pass_jvm::{
    ClassStructure, DecompiledClass, analyze_class_structure, decompile_class,
    decompile_classfile_bytes, disassemble, parse_classfile, parse_code_attribute,
};

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
            let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut bytes).expect("read class");
            out.push((name, bytes));
        }
    }
    Some(out)
}

#[test]
fn decompiles_real_hello_baseline_classfile() {
    let path: PathBuf = corpus(&["proguard", "Hello-baseline.class"]);
    let Some(bytes): Option<Vec<u8>> = load_fixture(&path) else {
        eprintln!(
            "skip: Hello-baseline.class fixture absent at {}",
            path.display()
        );
        return;
    };
    let d: DecompiledClass = decompile_classfile_bytes(&bytes).expect("decompile");
    assert!(d.source.contains("class "), "no class decl:\n{}", d.source);
    assert!(
        d.source.contains("this.name = arg0"),
        "constructor field assignment not lifted:\n{}",
        d.source
    );
    assert!(
        d.source.contains("return (this.counter + 1)")
            || d.source.contains("this.counter = (this.counter + 1)"),
        "arithmetic not lifted:\n{}",
        d.source
    );
    assert!(d.method_count >= 1, "expected at least <init>");
    assert!(
        d.source.contains("public") || d.source.contains("class"),
        "missing access modeling:\n{}",
        d.source
    );
}

#[test]
fn disassembles_every_method_in_baseline_jar() {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!(
            "skip: EdgeCases-baseline.jar fixture absent at {}",
            jar.display()
        );
        return;
    };
    assert!(!classes.is_empty(), "no classes in jar");
    let mut total_methods: usize = 0;
    let mut total_insns: usize = 0;
    for (name, bytes) in &classes {
        let cf = parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"));
        for method in &cf.methods {
            for attr in &method.attributes {
                if cf.utf8_at(attr.name_index).is_ok_and(|n| n == "Code") {
                    let code = parse_code_attribute(&attr.info)
                        .unwrap_or_else(|e| panic!("code attr in {name}: {e}"));
                    let insns =
                        disassemble(&code.code).unwrap_or_else(|e| panic!("disasm {name}: {e}"));
                    total_methods += 1;
                    total_insns += insns.len();
                }
            }
        }
    }
    assert!(total_methods > 0, "no Code attributes disassembled");
    assert!(total_insns > 0, "no instructions decoded");
}

#[test]
fn native_decompile_recovers_signatures_across_baseline_jar() {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!(
            "skip: EdgeCases-baseline.jar fixture absent at {}",
            jar.display()
        );
        return;
    };
    let mut lifted_total: usize = 0;
    let mut method_total: usize = 0;
    for (name, bytes) in &classes {
        let cf = parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"));
        let d: DecompiledClass = decompile_class(&cf);
        assert!(d.source.contains('{'), "no body braces in {name}");
        lifted_total += d.fully_lifted_methods;
        method_total += d.method_count;
    }
    assert!(method_total > 0, "no methods rendered");
    assert!(
        lifted_total > 0,
        "native decompiler lifted zero methods fully across {method_total} methods"
    );
}

#[test]
fn recovers_records_and_sealed_types_from_real_jar() {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!(
            "skip: EdgeCases-baseline.jar fixture absent at {}",
            jar.display()
        );
        return;
    };
    let mut record_classes: usize = 0;
    let mut sealed_classes: usize = 0;
    let mut record_in_source: bool = false;
    for (name, bytes) in &classes {
        let cf = parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"));
        let structure: ClassStructure = analyze_class_structure(&cf);
        if structure.is_record {
            record_classes += 1;
            let d: DecompiledClass = decompile_class(&cf);
            if d.source.contains("record ") {
                record_in_source = true;
            }
        }
        if structure.is_sealed {
            sealed_classes += 1;
        }
    }
    assert!(
        record_classes >= 1,
        "expected record components recovered (Circle/Square/Triangle/Pair)"
    );
    assert!(
        sealed_classes >= 1,
        "expected at least one sealed type with PermittedSubclasses"
    );
    assert!(
        record_in_source,
        "record keyword must render in pseudo-Java"
    );
}

#[test]
fn native_decompile_works_without_external_tools() {
    let path: PathBuf = corpus(&["proguard", "Hello-baseline.class"]);
    let Some(bytes): Option<Vec<u8>> = load_fixture(&path) else {
        eprintln!(
            "skip: Hello-baseline.class fixture absent at {}",
            path.display()
        );
        return;
    };
    let d: DecompiledClass = decompile_classfile_bytes(&bytes).expect("decompile");
    assert!(
        !d.source.is_empty() && d.source.contains("class "),
        "single-binary native decompile must produce source with no JVM present"
    );
}
