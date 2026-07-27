#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;

use disrobe_pass_jvm::dex2jar::{Dex2JarResult, TranslatedClass};
use disrobe_pass_jvm::{ClassFile, parse_classfile, translate_dex_bytes};

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    for part in parts {
        p.push(part);
    }
    p
}

fn baseline_classes() -> BTreeMap<String, Vec<u8>> {
    let bytes: Vec<u8> =
        std::fs::read(corpus(&["jvm", "megafile", "EdgeCases-baseline.jar"])).expect("read jar");
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(bytes);
    let mut zip: zip::ZipArchive<std::io::Cursor<Vec<u8>>> =
        zip::ZipArchive::new(cursor).expect("open jar");
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..zip.len() {
        let mut f: zip::read::ZipFile<'_> = zip.by_index(i).expect("entry");
        let name: String = f.name().to_string();
        if name.ends_with(".class") {
            let mut buf: Vec<u8> = Vec::new();
            f.read_to_end(&mut buf).expect("read class");
            out.insert(name[..name.len() - 6].to_string(), buf);
        }
    }
    out
}

fn baseline_method_keys(class_bytes: &[u8]) -> BTreeSet<(String, String)> {
    let cf: ClassFile = parse_classfile(class_bytes).expect("parse baseline class");
    let mut keys: BTreeSet<(String, String)> = BTreeSet::new();
    for m in &cf.methods {
        let name: String = cf.utf8_at(m.name_index).expect("name").to_string();
        let desc: String = cf.utf8_at(m.descriptor_index).expect("desc").to_string();
        keys.insert((name, desc));
    }
    keys
}

fn translated_method_keys(class: &TranslatedClass) -> BTreeSet<(String, String)> {
    class
        .methods
        .iter()
        .map(|m| (m.name.clone(), m.descriptor.clone()))
        .collect()
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[test]
fn real_jvm_javap_accepts_translated_classes() {
    use disrobe_pass_jvm::assemble_jar;

    let Some(javap): Option<PathBuf> = find_on_path("javap") else {
        eprintln!("SKIP: javap (JDK) not on PATH - dex2jar bytecode validity unverified by JVM");
        return;
    };
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate");
    let jar: Vec<u8> = assemble_jar(&result).expect("assemble jar");

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_dex2jar_javap")
            .expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let jar_path: PathBuf = dir.join("translated.jar");
    std::fs::write(&jar_path, &jar).expect("write jar");

    for class_name in [
        "EdgeCases$Adder",
        "EdgeCases$Circle",
        "EdgeCases$Pair",
        "EdgeCases$Triangle",
        "EdgeCases$Vector2D",
    ] {
        let output: std::process::Output = std::process::Command::new(&javap)
            .arg("-p")
            .arg("-cp")
            .arg(&jar_path)
            .arg(class_name)
            .output()
            .expect("run javap");
        assert!(
            output.status.success(),
            "javap rejected translated class {class_name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(class_name.rsplit('$').next().unwrap_or(class_name))
                || stdout.contains("class")
                || stdout.contains("interface"),
            "javap output for {class_name} unexpectedly empty: {stdout}"
        );
    }
}

fn is_d8_relocated(name: &str, descriptor: &str) -> bool {
    name == "<clinit>"
        || (name == "values" && descriptor.starts_with("()["))
        || (name == "valueOf")
        || name.starts_with("lambda$")
        || name.starts_with("$values")
}

#[test]
fn every_baseline_class_is_present_in_dex2jar_output() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate");

    let translated_names: BTreeSet<String> = result
        .classes
        .iter()
        .map(|c: &TranslatedClass| c.internal_name.clone())
        .collect();

    let baseline: BTreeMap<String, Vec<u8>> = baseline_classes();
    assert!(!baseline.is_empty(), "baseline jar must contain classes");

    for class_name in baseline.keys() {
        assert!(
            translated_names.contains(class_name),
            "baseline class {class_name} missing from dex2jar output"
        );
    }
}

#[test]
fn every_baseline_method_appears_somewhere_in_translation() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate");

    let mut all_translated: BTreeSet<(String, String)> = BTreeSet::new();
    for class in &result.classes {
        all_translated.extend(translated_method_keys(class));
    }

    let baseline: BTreeMap<String, Vec<u8>> = baseline_classes();
    let mut checked: usize = 0;
    for baseline_bytes in baseline.values() {
        for (name, descriptor) in baseline_method_keys(baseline_bytes) {
            if is_d8_relocated(&name, &descriptor) {
                continue;
            }
            checked += 1;
            assert!(
                all_translated.contains(&(name.clone(), descriptor.clone())),
                "baseline method {name}{descriptor} not found anywhere in dex2jar output \
                 (D8 may relocate private/static into a $-CC companion, but it must still exist)"
            );
        }
    }
    assert!(
        checked > 50,
        "must cross-check a meaningful number of methods, got {checked}"
    );
}

#[test]
fn translated_jar_is_self_consistent_and_reparsable() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate");
    assert!(result.method_total > 0, "must translate some methods");

    for (name, class_bytes) in &result.jar_entries {
        assert!(name.ends_with(".class"));
        assert_eq!(
            &class_bytes[..4],
            &[0xCA, 0xFE, 0xBA, 0xBE],
            "{name} must carry the class magic"
        );
        let cf: ClassFile =
            parse_classfile(class_bytes).unwrap_or_else(|e| panic!("reparse {name}: {e}"));
        assert_eq!(cf.major_version, 52, "{name} must be class major 52");
    }
}

#[test]
fn superclass_relationships_match_baseline() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate");
    let by_name: BTreeMap<String, &TranslatedClass> = result
        .classes
        .iter()
        .map(|c: &TranslatedClass| (c.internal_name.clone(), c))
        .collect();

    let pair: &&TranslatedClass = by_name.get("EdgeCases$Pair").expect("Pair record present");
    assert!(
        pair.super_name == "java/lang/Record"
            || pair.super_name == "com/android/tools/r8/RecordTag",
        "EdgeCases$Pair is a record; D8 desugars java/lang/Record to RecordTag, got {}",
        pair.super_name
    );

    let adder: &&TranslatedClass = by_name
        .get("EdgeCases$Adder")
        .expect("Adder interface present");
    assert!(adder.is_interface(), "EdgeCases$Adder must be an interface");
    assert!(
        adder
            .methods
            .iter()
            .any(|m| m.name == "add" && m.descriptor == "(II)I"),
        "Adder must declare abstract add(II)I even without code"
    );
}
