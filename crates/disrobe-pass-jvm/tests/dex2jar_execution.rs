#![allow(clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::dex::parse as parse_dex;
use disrobe_pass_jvm::{Dex2JarResult, translate_dex_bytes};

const BUILD_STUB: &str = "package android.os;\n\npublic final class Build {\n    private Build() {}\n\n    public static final class VERSION {\n        private VERSION() {}\n\n        public static final int SDK_INT = 34;\n    }\n}\n";

fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

fn write_jar(path: &Path, entries: &std::collections::BTreeMap<String, Vec<u8>>) {
    let file: std::fs::File = std::fs::File::create(path).expect("create jar");
    let mut writer: zip::ZipWriter<std::fs::File> = zip::ZipWriter::new(file);
    for (name, bytes) in entries {
        writer
            .start_file(name.as_str(), zip::write::SimpleFileOptions::default())
            .expect("start jar entry");
        writer.write_all(bytes).expect("write jar entry");
    }
    writer.finish().expect("finish jar");
}

fn compile_stub(scratch: &Path) -> PathBuf {
    let source: PathBuf = scratch.join("stub-src/android/os/Build.java");
    std::fs::create_dir_all(source.parent().expect("stub dir")).expect("stub dir");
    std::fs::write(&source, BUILD_STUB).expect("write stub");
    let classes: PathBuf = scratch.join("stub-classes");
    std::fs::create_dir_all(&classes).expect("stub classes dir");
    let javac: Output = Command::new("javac")
        .arg("-d")
        .arg(&classes)
        .arg(&source)
        .output()
        .expect("javac on PATH");
    assert!(
        javac.status.success(),
        "the android.os.Build stub compiles: {}",
        String::from_utf8_lossy(&javac.stderr)
    );
    classes
}

fn run_verified(jar: &Path, stub: &Path, main: &str) -> (bool, String, String) {
    let separator: &str = if cfg!(windows) { ";" } else { ":" };
    let classpath: String = format!("{}{separator}{}", jar.display(), stub.display());
    let run: Output = Command::new("java")
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(classpath)
        .arg(main)
        .output()
        .expect("java on PATH");
    (
        run.status.success(),
        String::from_utf8_lossy(&run.stdout).into_owned(),
        String::from_utf8_lossy(&run.stderr).into_owned(),
    )
}

fn with_sorted_map_entries(output: &str) -> String {
    output
        .lines()
        .map(|line: &str| match (line.find('{'), line.rfind('}')) {
            (Some(open), Some(close)) if open < close && line[open + 1..close].contains('=') => {
                let mut entries: Vec<&str> = line[open + 1..close].split(", ").collect();
                entries.sort_unstable();
                format!(
                    "{}{{{}}}{}",
                    &line[..open],
                    entries.join(", "),
                    &line[close + 1..]
                )
            }
            _ => line.to_owned(),
        })
        .collect::<Vec<String>>()
        .join(
            "
",
        )
}

#[test]
fn the_translated_edge_cases_dex_runs_equal_to_the_javac_baseline_under_the_verifier() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus("jvm/dex/EdgeCases.dex")).expect("read dex");
    let dex = parse_dex(&dex_bytes).expect("parse dex");
    for interface in [
        "LEdgeCases$Shape;",
        "LEdgeCases$Adder;",
        "LEdgeCases$Repository;",
    ] {
        assert!(
            dex.class_interfaces.contains(interface),
            "{interface} is parsed as an interface: {:?}",
            dex.class_interfaces
        );
    }
    assert!(!dex.class_interfaces.contains("LEdgeCases;"));
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate dex");
    assert!(result.code_scan_complete, "{:#?}", result.diagnostics);
    assert_eq!(
        result.stubbed_body_count, 0,
        "every method body translated: {:#?}",
        result.diagnostics
    );
    let scratch: ScratchDir = ScratchDir::create("dex2jar-execution").expect("scratch dir");
    let jar: PathBuf = scratch.path().join("translated.jar");
    write_jar(&jar, &result.jar_entries);
    let stub: PathBuf = compile_stub(scratch.path());
    let (baseline_ok, baseline_out, baseline_err) = run_verified(
        &corpus("jvm/megafile/EdgeCases-baseline.jar"),
        &stub,
        "EdgeCases",
    );
    assert!(baseline_ok, "the javac baseline runs: {baseline_err}");
    assert!(
        baseline_out.lines().count() > 100,
        "the baseline prints its sections"
    );
    let (translated_ok, translated_out, translated_err) = run_verified(&jar, &stub, "EdgeCases");
    assert!(
        translated_ok,
        "the translated jar runs under -Xverify:all: {translated_err}"
    );
    assert_eq!(
        with_sorted_map_entries(&translated_out),
        with_sorted_map_entries(&baseline_out),
        "the translated program prints what the javac baseline prints (map entries sorted, because Map.copyOf salts its iteration order per JVM run)"
    );
}

#[test]
fn a_dex_without_static_interface_calls_still_translates_and_runs() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus("jvm/dex/Hello.dex")).expect("read dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate dex");
    assert_eq!(result.stubbed_body_count, 0);
    let scratch: ScratchDir = ScratchDir::create("dex2jar-execution-hello").expect("scratch dir");
    let jar: PathBuf = scratch.path().join("hello.jar");
    write_jar(&jar, &result.jar_entries);
    let stub: PathBuf = compile_stub(scratch.path());
    let main: String = result
        .classes
        .iter()
        .find(|c: &&disrobe_pass_jvm::TranslatedClass| {
            c.methods
                .iter()
                .any(|m: &disrobe_pass_jvm::TranslatedMethod| m.name == "main")
        })
        .map(|c: &disrobe_pass_jvm::TranslatedClass| c.internal_name.replace('/', "."))
        .expect("a class with a main method");
    let (ok, out, err) = run_verified(&jar, &stub, &main);
    assert!(ok, "{err}");
    assert!(!out.is_empty(), "the program prints something");
}
