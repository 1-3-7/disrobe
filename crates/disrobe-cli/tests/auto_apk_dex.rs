#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

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
fn tmp_path(name: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let purpose: String = format!("disrobe-apk-dex-{name}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let path: PathBuf = scratch.path().join("payload");
    (scratch, path)
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
    pack_apk_with_entries(dex_bytes, &[])
}

fn pack_apk_with_entries(dex_bytes: &[u8], extra_entries: &[(&str, &[u8])]) -> Vec<u8> {
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
    for (path, bytes) in extra_entries {
        writer
            .start_file(*path, options)
            .unwrap_or_else(|e| panic!("start {path} entry: {e}"));
        writer
            .write_all(bytes)
            .unwrap_or_else(|e| panic!("write {path} bytes: {e}"));
    }
    writer.finish().expect("finish apk zip").into_inner()
}

fn read_recovered_jvm_source(out_dir: &Path) -> String {
    let candidate: PathBuf = out_dir.join("extracted").join("classes.java");
    std::fs::read_to_string(&candidate).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "no recovered jvm source child at {candidate:?}; the apk->dex inner-child re-feed did \
             not deliver classes.dex to jvm.classify whose extract_children surfaces the \
             decompiled java ({e})"
        )
    })
}

fn picked_passes(doc: &serde_json::Value) -> Vec<String> {
    doc.get("nodes")
        .and_then(serde_json::Value::as_array)
        .map(|nodes: &Vec<serde_json::Value>| {
            nodes
                .iter()
                .filter_map(|n: &serde_json::Value| {
                    n.get("pass")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

#[test]
fn auto_chain_apk_dex_recovers_decompiled_class_tokens() {
    let dex_fixture: PathBuf = corpus_path("jvm/dex/Hello.dex");
    assert!(
        dex_fixture.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        dex_fixture.display()
    );
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing \
         {} would leave this case driving nothing",
        bin.display()
    );

    let dex_bytes: Vec<u8> = std::fs::read(&dex_fixture)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read {dex_fixture:?}: {e}"));

    let apk_bytes: Vec<u8> = pack_apk(&dex_bytes);
    let (_apk_path_scratch, apk_base): (disrobe_core::scratch::ScratchDir, PathBuf) =
        tmp_path("app");
    let apk_path: PathBuf = apk_base.with_extension("apk");
    std::fs::write(&apk_path, &apk_bytes)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot write synth apk {apk_path:?}: {e}"));

    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) = tmp_path("out");
    let proc_out: std::process::Output = run_chain_capture(&apk_path, &out_dir);
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let json: String = read_chain_json(&out_dir);
    let doc: serde_json::Value = serde_json::from_str(&json)
        .unwrap_or_else(|e: serde_json::Error| panic!("chain.json is not valid json: {e}"));
    let passes: Vec<String> = picked_passes(&doc);

    assert!(
        passes.iter().any(|p: &String| p == "mobile.classify"),
        "the apk container must be fanned out by mobile.classify at depth 1; passes: {passes:?}"
    );
    assert!(
        passes.iter().any(|p: &String| p == "jvm.classify"),
        "the extracted classes.dex child must be re-fed to jvm.classify (inner-child re-feed); \
         passes: {passes:?}"
    );
    assert!(
        json.contains("android-apk-dex"),
        "expected android-apk-dex container tag in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );
    assert!(
        json.contains("android-dex"),
        "expected android-dex format tag (jvm.classify on the re-fed dex) in chain.json; \
         got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );

    let stage: String = read_recovered_jvm_source(&out_dir);
    let has_hello_class: bool = stage.contains("class Hello");
    let has_greeter_class: bool = stage.contains("class Greeter");
    let has_main: bool = stage.contains("main");
    assert!(
        (has_hello_class || has_greeter_class) && has_main,
        "the jvm.classify source child must recover real decompiled java for the program (class Hello/class Greeter and main) \
         from the dex extracted out of the apk by the chain; \
         has_hello_class={has_hello_class} has_greeter_class={has_greeter_class} has_main={has_main}; \
         first 600 chars: {prefix:?}",
        prefix = stage.chars().take(600).collect::<String>(),
    );
    assert!(
        !stage.trim_start().starts_with('{') && !stage.contains("\"smali_text\""),
        "the jvm.classify source child must be real java source, not the old JvmExtract summary json",
    );

    let reflection_sidecar: PathBuf = out_dir
        .join("extracted")
        .join("jvm-reflection-strings.json");
    let manifest_sidecar: PathBuf = out_dir.join("extracted").join("jvm-manifest.json");
    assert!(
        manifest_sidecar.exists(),
        "auto must now emit the jvm classify manifest sidecar at {manifest_sidecar:?} so it \
         matches the dedicated `jvm decompile` manifest.json"
    );
    let _ = reflection_sidecar;

    let _ = std::fs::remove_file(&apk_path);
    let _ = std::fs::remove_dir_all(&out_dir);

    eprintln!(
        "auto_apk_dex: apk -> mobile.classify(android-apk-dex) -> [classes.dex re-fed] -> \
         jvm.classify(android-dex) -> java ({} bytes child); Hello={has_hello_class} \
         Greeter={has_greeter_class} main={has_main}",
        stage.len(),
    );
}

const JNI_REGISTER_X64_SO: &[u8] =
    include_bytes!("../../disrobe-pass-jvm/tests/fixtures/jni_register/libjnireg_x64.so");

#[test]
fn auto_chain_apk_links_registered_natives_against_the_embedded_native_library() {
    let dex_fixture: PathBuf = corpus_path("jvm/dex/Hello.dex");
    assert!(
        dex_fixture.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        dex_fixture.display()
    );
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing \
         {} would leave this case driving nothing",
        bin.display()
    );

    let dex_bytes: Vec<u8> = std::fs::read(&dex_fixture)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read {dex_fixture:?}: {e}"));

    let apk_bytes: Vec<u8> = pack_apk_with_entries(
        &dex_bytes,
        &[("lib/x86_64/libjnireg_x64.so", JNI_REGISTER_X64_SO)],
    );
    let (_apk_path_scratch, apk_base): (disrobe_core::scratch::ScratchDir, PathBuf) =
        tmp_path("jni-app");
    let apk_path: PathBuf = apk_base.with_extension("apk");
    std::fs::write(&apk_path, &apk_bytes)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot write synth apk {apk_path:?}: {e}"));

    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        tmp_path("jni-out");
    let proc_out: std::process::Output = run_chain_capture(&apk_path, &out_dir);
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let sidecar_path: PathBuf = out_dir.join("extracted").join("jni-link.json");
    assert!(
        sidecar_path.exists(),
        "auto must link the apk's embedded classes.dex against its embedded native library \
         without the user naming either side; expected {sidecar_path:?} to exist"
    );
    let sidecar_text: String = std::fs::read_to_string(&sidecar_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {sidecar_path:?}: {e}"));
    let sidecar: serde_json::Value = serde_json::from_str(&sidecar_text)
        .unwrap_or_else(|e: serde_json::Error| panic!("jni-link.json is not valid json: {e}"));

    let registered: &Vec<serde_json::Value> = sidecar["surface"]["registered_natives"]
        .as_array()
        .expect("surface.registered_natives array");
    assert_eq!(
        registered.len(),
        4,
        "the four JNINativeMethod entries recovered from the committed fixture must reach the \
         auto chain sidecar; got: {sidecar_text}"
    );
    let names: Vec<&str> = registered
        .iter()
        .filter_map(|entry: &serde_json::Value| entry["name"].as_str())
        .collect();
    for want in ["nativeAdd", "nativeLen", "nativeNoop", "hiddenMul"] {
        assert!(
            names.contains(&want),
            "recovered RegisterNatives entries must include {want}; got {names:?}"
        );
    }

    let _ = std::fs::remove_file(&apk_path);
    let _ = std::fs::remove_dir_all(&out_dir);

    eprintln!(
        "auto_apk_dex jni: apk(classes.dex + lib/x86_64/libjnireg_x64.so) -> \
         mobile.classify(android-apk-dex) -> jni-link.json with {} registered natives",
        registered.len(),
    );
}
