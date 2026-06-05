#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use zip::ZipArchive;
use zip::write::{FileOptions, ZipWriter};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

#[allow(clippy::disallowed_methods)]
fn tmp_path(name: &str) -> PathBuf {
    let stamp: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    let pid: u32 = std::process::id();
    std::env::temp_dir().join(format!("disrobe-apk-dex-{name}-{pid}-{stamp}"))
}

fn run_chain_capture(input: &Path, out: &Path) -> std::process::Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    Command::new(&bin)
        .arg("chain")
        .arg(input)
        .arg("--out")
        .arg(out)
        .arg("--chain")
        .arg("auto:8")
        .arg("--capture-stages")
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

fn read_chain_json(out_dir: &Path) -> String {
    let p: PathBuf = out_dir.join("chain.json");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read chain.json at {p:?}: {e}"))
}

fn pack_apk(dex_bytes: &[u8]) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::with_capacity(dex_bytes.len() + 256));
    let mut writer: ZipWriter<Cursor<Vec<u8>>> = ZipWriter::new(cursor);
    let options: FileOptions<'_, ()> =
        FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("classes.dex", options)
        .expect("start classes.dex entry");
    writer
        .write_all(dex_bytes)
        .expect("write classes.dex bytes");
    writer
        .start_file("AndroidManifest.xml", options)
        .expect("start manifest entry");
    writer
        .write_all(b"<manifest package=\"com.disrobe.hello\"/>")
        .expect("write manifest bytes");
    writer.finish().expect("finish apk zip").into_inner()
}

fn extract_classes_dex(apk_bytes: &[u8]) -> Vec<u8> {
    let mut archive: ZipArchive<Cursor<&[u8]>> =
        ZipArchive::new(Cursor::new(apk_bytes)).expect("open synth apk as zip");
    let mut entry: zip::read::ZipFile<'_> = archive
        .by_name("classes.dex")
        .expect("apk must contain classes.dex");
    let mut buf: Vec<u8> = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut buf)
        .expect("read classes.dex from apk");
    buf
}

fn read_terminal_jvm_stage(out_dir: &Path) -> String {
    let mut found: Option<PathBuf> = None;
    let mut best_ordinal: u32 = 0;
    let entries: std::fs::ReadDir = std::fs::read_dir(out_dir)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read out dir {out_dir:?}: {e}"));
    for entry in entries {
        let entry: std::fs::DirEntry =
            entry.unwrap_or_else(|e: std::io::Error| panic!("dir entry error: {e}"));
        let name: String = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with("-jvm-classify") {
            continue;
        }
        let ordinal: u32 = name
            .split('-')
            .next()
            .and_then(|s: &str| s.parse::<u32>().ok())
            .unwrap_or(0);
        if ordinal >= best_ordinal {
            best_ordinal = ordinal;
            found = Some(entry.path().join("output.bin"));
        }
    }
    let stage: PathBuf = found.unwrap_or_else(|| {
        panic!(
            "no NN-jvm-classify stage dir under {out_dir:?}; chain did not dispatch jvm.classify"
        )
    });
    std::fs::read_to_string(&stage)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read stage {stage:?}: {e}"))
}

#[test]
fn auto_chain_apk_dex_recovers_smali_class_tokens() {
    let dex_fixture: PathBuf = corpus_path("jvm/dex/Hello.dex");
    if !dex_fixture.exists() {
        eprintln!("SKIP: fixture missing: {dex_fixture:?}");
        return;
    }
    let bin: PathBuf = cargo_bin();
    if !bin.exists() {
        eprintln!("SKIP: disrobe binary missing at {bin:?}");
        return;
    }

    let dex_bytes: Vec<u8> = std::fs::read(&dex_fixture)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read {dex_fixture:?}: {e}"));

    let apk_bytes: Vec<u8> = pack_apk(&dex_bytes);
    let extracted_dex: Vec<u8> = extract_classes_dex(&apk_bytes);
    assert_eq!(
        extracted_dex, dex_bytes,
        "classes.dex extracted from synth apk must be byte-identical to Hello.dex"
    );

    let dex_path: PathBuf = tmp_path("classes").with_extension("dex");
    std::fs::write(&dex_path, &extracted_dex)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot write extracted dex {dex_path:?}: {e}"));

    let out_dir: PathBuf = tmp_path("out");
    let proc_out: std::process::Output = run_chain_capture(&dex_path, &out_dir);
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let json: String = read_chain_json(&out_dir);
    assert!(
        json.contains("jvm.classify"),
        "expected jvm.classify pass in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );
    assert!(
        json.contains("android-dex"),
        "expected android-dex format tag in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );

    let stage: String = read_terminal_jvm_stage(&out_dir);
    let has_hello_class: bool = stage.contains(".class LHello;");
    let has_greeter_class: bool = stage.contains(".class LGreeter;");
    let has_main: bool = stage.contains("main");
    assert!(
        (has_hello_class || has_greeter_class) && has_main,
        "terminal jvm.classify stage must recover real smali class tokens (.class LHello;/.class LGreeter; and main); \
         has_hello_class={has_hello_class} has_greeter_class={has_greeter_class} has_main={has_main}; \
         first 600 chars: {prefix:?}",
        prefix = stage.chars().take(600).collect::<String>(),
    );

    let _ = std::fs::remove_file(&dex_path);
    let _ = std::fs::remove_dir_all(&out_dir);

    eprintln!(
        "auto_apk_dex: recovered smali ({} bytes stage); LHello={has_hello_class} LGreeter={has_greeter_class} main={has_main}",
        stage.len(),
    );
}
