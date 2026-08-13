#![allow(clippy::expect_used)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path: OsString = std::env::var_os("PATH")?;
    let extensions: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    std::env::split_paths(&path).find_map(|directory: PathBuf| {
        extensions.iter().find_map(|extension: &&str| {
            let candidate: PathBuf = directory.join(format!("{name}{extension}"));
            candidate.is_file().then_some(candidate)
        })
    })
}

#[test]
fn real_d8_default_interface_companion_returns_to_source_shape() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let shape: &String = recovered
        .sources
        .get("EdgeCases/Shape.java")
        .expect("recover Shape");

    assert!(shape.contains("public interface Shape"), "{shape}");
    assert!(shape.contains("default String label()"), "{shape}");
    assert!(shape.contains("new StringBuilder(\"shape:\")"), "{shape}");
    assert!(shape.contains("this.getClass()"), "{shape}");
    assert!(!shape.contains("abstract String label()"), "{shape}");
    assert!(
        !recovered
            .sources
            .contains_key("EdgeCases/Shape$_u002D_CC.java")
    );

    for implementation in ["Circle", "Square", "Triangle", "EmptyShape"] {
        let path: String = format!("EdgeCases/{implementation}.java");
        let source: &String = recovered
            .sources
            .get(&path)
            .expect("recover implementation");
        assert!(
            source.contains("implements EdgeCases.Shape"),
            "{path}: {source}"
        );
        assert!(!source.contains("$default$label"), "{path}: {source}");
        assert!(!source.contains(" String label()"), "{path}: {source}");
    }

    assert!(
        recovered
            .sources
            .contains_key("EdgeCases/Repository$_u002D_CC.java"),
        "a companion with non-default static methods must remain visible"
    );

    let javac: PathBuf = find_on_path("javac")
        .expect("the D8 default-interface recovery gate requires javac on PATH");
    let scratch: ScratchDir = ScratchDir::create("d8-default-interface").expect("create scratch");
    let package: PathBuf = scratch.path().join("EdgeCases");
    std::fs::create_dir_all(&package).expect("create Java package directory");
    let source_path: PathBuf = package.join("Shape.java");
    std::fs::write(&source_path, shape).expect("write recovered interface");
    let compiled: Output = Command::new(&javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "recovered D8 interface did not compile under javac:\n{}\n{shape}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let probe_path: PathBuf = package.join("Probe.java");
    let probe: &str = "package EdgeCases; final class Probe implements Shape { public double area() { return 0.0; } public static void main(String[] args) { if (!new Probe().label().equals(\"shape:probe\")) throw new AssertionError(); } }";
    std::fs::write(&probe_path, probe).expect("write Java behavior probe");
    let compiled_probe: Output = Command::new(&javac)
        .arg("-cp")
        .arg(scratch.path())
        .arg("-d")
        .arg(scratch.path())
        .arg(&probe_path)
        .output()
        .expect("compile Java behavior probe");
    assert!(
        compiled_probe.status.success(),
        "behavior probe did not compile:\n{}",
        String::from_utf8_lossy(&compiled_probe.stderr)
    );
    let java: PathBuf =
        find_on_path("java").expect("the D8 default-interface recovery gate requires java on PATH");
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("EdgeCases.Probe")
        .output()
        .expect("run Java behavior probe");
    assert!(
        executed.status.success(),
        "recovered default method changed behavior:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
