#![cfg(feature = "jvm")]
#![allow(clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{cli_binary, run_disrobe, temp_dir, temp_path};
use disrobe_pass_jvm::{assemble_jar, translate_dex_bytes};
use sha2::{Digest, Sha256};

const EDGE_CASES_DEX_SHA256: &str =
    "fdc012bd9b9596256ee2bb319ef3e215a34b6d58c3b0856d7ea8bdb290910e26";
const D8_FINALLY_SOURCE: &str =
    include_str!("../../disrobe-pass-jvm/tests/fixtures/d8_finally_nested/D8FinallyNested.java");
const D8_FINALLY_RUNNER: &str = "public final class Runner { public static void main(String[] a) { int l=Integer.parseInt(a[0]), r=Integer.parseInt(a[1]), s=Integer.parseInt(a[2]); D8FinallyNested.counter=s; try { System.out.print(\"value:\"+D8FinallyNested.run(l,r)+\":counter:\"+D8FinallyNested.counter); } catch(Throwable e) { System.out.print(\"throw:\"+e.getClass().getName()+\":counter:\"+D8FinallyNested.counter); } } }";

fn edge_cases_dex() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/jvm/dex/EdgeCases.dex");
    path
}

fn d8_finally_dex() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-pass-jvm/tests/fixtures/d8_finally_nested/D8FinallyNested.dex")
}

fn compile_runner(directory: &Path, sources: &[PathBuf]) {
    let output = Command::new("javac")
        .arg("-proc:none")
        .arg("-cp")
        .arg(directory)
        .arg("-d")
        .arg(directory)
        .args(sources)
        .output()
        .expect("the runtime gate requires javac on PATH");
    assert!(
        output.status.success(),
        "javac: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_runner(directory: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("java")
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(directory)
        .arg("Runner")
        .args(args)
        .output()
        .expect("the runtime gate requires java on PATH");
    assert!(
        output.status.success(),
        "java: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn jvm_dex2jar_rejects_a_non_dex_input_without_creating_output() {
    let (input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jvm-dex2jar-non-dex", "bin");
    std::fs::write(&input, b"not a dex").expect("write malformed input");
    let output_scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-dex2jar-non-dex-output");
    let output: PathBuf = output_scratch.path().join("out");
    let run = run_disrobe(&[
        "jvm",
        "dex2-jar",
        input.to_str().expect("utf8 input"),
        "--out",
        output.to_str().expect("utf8 output"),
    ]);
    assert_ne!(run.code, 0, "non-DEX input must be rejected");
    assert!(
        !output.exists(),
        "rejected input must not materialize output"
    );
    drop(input_scratch);
}

#[test]
fn jvm_dex2jar_rejects_a_truncated_dex_without_creating_output() {
    let (input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jvm-dex2jar-truncated", "dex");
    let mut bytes: Vec<u8> = std::fs::read(d8_finally_dex()).expect("read D8 fixture");
    bytes.truncate(112);
    std::fs::write(&input, bytes).expect("write truncated DEX");
    let output_scratch: disrobe_core::scratch::ScratchDir =
        temp_dir("jvm-dex2jar-truncated-output");
    let output: PathBuf = output_scratch.path().join("out");
    let run = run_disrobe(&[
        "jvm",
        "dex2-jar",
        input.to_str().expect("utf8 input"),
        "--out",
        output.to_str().expect("utf8 output"),
    ]);
    assert_ne!(run.code, 0, "truncated DEX input must be rejected");
    assert!(
        !output.exists(),
        "rejected input must not materialize output"
    );
    drop(input_scratch);
}

fn jar_classes(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).expect("open translated jar");
    let mut classes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry: zip::read::ZipFile<'_> = archive.by_index(index).expect("jar entry");
        let name: String = entry.name().to_owned();
        if Path::new(&name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("class"))
        {
            let mut bytes: Vec<u8> = Vec::new();
            entry.read_to_end(&mut bytes).expect("class bytes");
            classes.insert(name, bytes);
        }
    }
    classes
}

fn verify_classes_with_java(jar: &Path, entries: &BTreeMap<String, Vec<u8>>, directory: &Path) {
    let source: PathBuf = directory.join("VerifyTranslated.java");
    std::fs::write(
        &source,
        "public final class VerifyTranslated { public static void main(String[] names) throws Exception { for (String name : names) Class.forName(name, false, VerifyTranslated.class.getClassLoader()); } }",
    )
    .expect("write verifier harness");
    let javac = Command::new("javac")
        .arg(&source)
        .current_dir(directory)
        .output()
        .expect("the verifier gate requires javac on PATH");
    assert!(
        javac.status.success(),
        "compile verifier harness: {}",
        String::from_utf8_lossy(&javac.stderr)
    );
    let separator: char = if cfg!(windows) { ';' } else { ':' };
    let classpath: String = format!("{}{separator}{}", jar.display(), directory.display());
    let names: Vec<String> = entries
        .keys()
        .map(|entry| entry.trim_end_matches(".class").replace('/', "."))
        .collect();
    let java = Command::new("java")
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(classpath)
        .arg("VerifyTranslated")
        .args(&names)
        .output()
        .expect("the verifier gate requires java on PATH");
    assert!(
        java.status.success(),
        "JVM verifier rejected translated classes: {}",
        String::from_utf8_lossy(&java.stderr)
    );
}

#[test]
fn jvm_dex2jar_writes_the_in_house_translation_without_an_external_backend() {
    let input: PathBuf = edge_cases_dex();
    assert!(
        input.is_file(),
        "the committed D8 fixture is required: {}",
        input.display()
    );
    assert!(
        cli_binary().is_file(),
        "the CLI binary must be built before this test"
    );

    let dex: Vec<u8> = std::fs::read(&input).expect("read committed D8 fixture");
    assert_eq!(format!("{:x}", Sha256::digest(&dex)), EDGE_CASES_DEX_SHA256);
    let direct = translate_dex_bytes(&dex).expect("direct in-house translation");
    assert_eq!(direct.method_total, 370);
    assert_eq!(direct.bodies_recovered, 354);
    assert_eq!(direct.stubbed_body_count, 1);
    let partial_methods: Vec<_> = direct
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.method.is_some())
        .collect();
    assert_eq!(partial_methods.len(), direct.stubbed_body_count);
    assert_eq!(
        partial_methods[0].reason,
        "DR-JVM-0093: linear and control-flow JVM emitters refused the decoded body"
    );
    let direct_jar: Vec<u8> = assemble_jar(&direct).expect("direct in-house jar assembly");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-dex2jar");
    let out: PathBuf = scratch.path().join("first");
    let second: PathBuf = scratch.path().join("second");

    let run = run_disrobe(&[
        "jvm",
        "dex2-jar",
        input.to_str().expect("utf8 input"),
        "--out",
        out.to_str().expect("utf8 output"),
    ]);
    assert_eq!(
        run.code, 0,
        "in-house DEX-to-JAR CLI failed: {}",
        run.stderr
    );
    assert!(run.stdout.contains("jvm dex2jar: PARTIAL"));
    assert!(run.stdout.contains("370 total, 354 recovered, 1 stubbed"));
    assert!(
        run.stdout
            .contains("code scan:    complete (0 decode error(s))")
    );
    assert!(run.stdout.contains("  partial:      "));

    let cli_jar: Vec<u8> = std::fs::read(out.join("classes.jar")).expect("CLI jar output");
    assert_eq!(
        cli_jar, direct_jar,
        "CLI JAR must be byte-identical to the direct API"
    );
    assert_eq!(
        jar_classes(&cli_jar),
        direct.jar_entries,
        "CLI class paths and bytes must match the direct API"
    );
    for (path, bytes) in &direct.jar_entries {
        assert_eq!(
            std::fs::read(out.join(path)).expect("CLI class tree entry"),
            *bytes,
            "CLI class tree differs at {path}"
        );
    }
    verify_classes_with_java(
        &out.join("classes.jar"),
        &direct.jar_entries,
        scratch.path(),
    );
    let second_run = run_disrobe(&[
        "jvm",
        "dex2-jar",
        input.to_str().expect("utf8 input"),
        "--out",
        second.to_str().expect("utf8 output"),
    ]);
    assert_eq!(
        second_run.code, 0,
        "second in-house DEX-to-JAR CLI failed: {}",
        second_run.stderr
    );
    assert_eq!(
        std::fs::read(second.join("classes.jar")).expect("second CLI jar output"),
        cli_jar,
        "repeated CLI JAR output must be byte-identical"
    );
    for (path, bytes) in &direct.jar_entries {
        assert_eq!(
            std::fs::read(second.join(path)).expect("second class tree entry"),
            *bytes
        );
    }
    let overwrite = run_disrobe(&[
        "jvm",
        "dex2-jar",
        input.to_str().expect("utf8 input"),
        "--out",
        out.to_str().expect("utf8 output"),
    ]);
    assert_ne!(
        overwrite.code, 0,
        "existing output directory must be refused"
    );
    assert_eq!(
        std::fs::read(out.join("classes.jar")).expect("preserved first jar"),
        cli_jar
    );
}

#[test]
fn jvm_dex2jar_runtime_matches_the_authored_d8_fixture_for_complete_bodies() {
    let dex: PathBuf = d8_finally_dex();
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jvm-dex2jar-runtime");
    let authored: PathBuf = scratch.path().join("authored");
    let translated: PathBuf = scratch.path().join("translated");
    std::fs::create_dir(&authored).expect("create authored output");
    let authored_source: PathBuf = authored.join("D8FinallyNested.java");
    let authored_runner: PathBuf = authored.join("Runner.java");
    std::fs::write(&authored_source, D8_FINALLY_SOURCE).expect("write authored source");
    std::fs::write(&authored_runner, D8_FINALLY_RUNNER).expect("write runner");
    compile_runner(&authored, &[authored_source, authored_runner]);
    let run = run_disrobe(&[
        "jvm",
        "dex2-jar",
        dex.to_str().expect("utf8 dex"),
        "--out",
        translated.to_str().expect("utf8 output"),
    ]);
    assert_eq!(run.code, 0, "D8 CLI translation: {}", run.stderr);
    let translated_runner: PathBuf = translated.join("Runner.java");
    std::fs::write(&translated_runner, D8_FINALLY_RUNNER).expect("write translated runner");
    compile_runner(&translated, &[translated_runner]);
    for args in [["9", "3", "2"], ["9", "0", "7"]] {
        assert_eq!(
            run_runner(&authored, &args),
            run_runner(&translated, &args),
            "runtime disagreement for {args:?}"
        );
    }
}
