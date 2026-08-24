#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

const DEX: &[u8] =
    include_bytes!("fixtures/d8_constructor_delegate/ConstructorDelegateProbe-min21.dex");
const AUTHORED: &str =
    include_str!("fixtures/d8_constructor_delegate/ConstructorDelegateProbe.java");
const PROVENANCE: &str = include_str!("fixtures/d8_constructor_delegate/provenance.toml");
const DEX_SHA256: &str = "a9d3f100af5da051ce970b429339fcac3b122c6b76380fcdaeac0eb27e2b7f76";
const SOURCE_SHA256: &str = "7484dc50536840091d14bea194e1a34808becf5e1f870e1e2780a74696db24cf";

fn recovered() -> DecompiledDex {
    let dex: DexFile = parse_dex(DEX).expect("parse trusted D8 fixture");
    decompile_dex(&dex, DEX)
}

fn recovered_probe(recovered: &DecompiledDex) -> &String {
    recovered
        .sources
        .values()
        .find(|source: &&String| source.contains("class ConstructorDelegateProbe"))
        .expect("recover the authored class")
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn compile_and_run(label: &str, sources: &[(PathBuf, String)]) -> Vec<u8> {
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let root: &std::path::Path = scratch.path();
    let mut source_paths: Vec<PathBuf> = Vec::with_capacity(sources.len() + 1);
    for (relative, source) in sources {
        let path: PathBuf = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("source has parent"))
            .expect("create source parent");
        std::fs::write(&path, source).expect("write Java source");
        source_paths.push(path);
    }
    let harness: PathBuf = root.join("fixtures/constructor/Harness.java");
    std::fs::write(
        &harness,
        "package fixtures.constructor; public final class Harness { public static void main(String[] args) { for (int[] pair : new int[][] {{3, 5}, {-7, 11}, {0, 0}}) { System.out.println(ConstructorDelegateProbe.create(new InputPair(pair[0], pair[1])).score()); } } }",
    )
    .expect("write Java harness");
    source_paths.push(harness);
    let compiled = Command::new("javac")
        .arg("-d")
        .arg(root)
        .args(&source_paths)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected {label}: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new("java")
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(root)
        .arg("fixtures.constructor.Harness")
        .output()
        .expect("run Java harness");
    assert!(
        executed.status.success(),
        "java rejected {label}: {}",
        String::from_utf8_lossy(&executed.stderr)
    );
    executed.stdout
}

#[test]
fn real_d8_same_class_constructor_delegation_uses_this_with_field_arguments() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), SOURCE_SHA256);
    assert!(PROVENANCE.contains("version = \"9.1.31\""));
    assert!(PROVENANCE.contains(DEX_SHA256));
    assert!(PROVENANCE.contains(SOURCE_SHA256));

    let recovered: DecompiledDex = recovered();
    let source: &String = recovered_probe(&recovered);
    let delegation: &str = "this(((fixtures.constructor.InputPair) arg0).left, ((fixtures.constructor.InputPair) arg0).right)";
    assert!(
        source.contains(delegation),
        "same-class constructor delegation must remain this(...) with ordered field reads:\n{source}"
    );
    assert!(source.contains("super()"), "{source}");
    assert!(
        source.contains("new fixtures.constructor.ConstructorDelegateProbe(arg0)"),
        "allocation-backed construction must remain new:\n{source}"
    );
    let constructor_start: usize = source
        .find("ConstructorDelegateProbe(fixtures.constructor.InputPair arg0)")
        .expect("delegating constructor");
    let constructor: &str = &source[constructor_start..];
    let body_start: usize = constructor.find('{').expect("constructor body") + 1;
    let delegation_start: usize = constructor.find(delegation).expect("delegation statement");
    assert!(
        constructor[body_start..delegation_start].trim().is_empty(),
        "delegation must be the first executable statement:\n{constructor}"
    );

    let recovered_sources: Vec<(PathBuf, String)> = recovered
        .sources
        .iter()
        .map(|(path, source): (&String, &String)| (PathBuf::from(path), source.clone()))
        .collect();
    let authored_sources: Vec<(PathBuf, String)> = vec![(
        PathBuf::from("fixtures/constructor/ConstructorDelegateProbe.java"),
        AUTHORED.to_owned(),
    )];
    let authored_stdout: Vec<u8> =
        compile_and_run("d8-constructor-delegate-authored", &authored_sources);
    let recovered_stdout: Vec<u8> =
        compile_and_run("d8-constructor-delegate-recovered", &recovered_sources);
    assert_eq!(
        String::from_utf8_lossy(&authored_stdout)
            .lines()
            .collect::<Vec<&str>>(),
        ["98", "-206", "0"]
    );
    assert_eq!(recovered_stdout, authored_stdout);
}
