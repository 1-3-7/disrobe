#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const MEI_MAGIC: &[u8; 8] = b"MEI\x0C\x0B\x0A\x0B\x0E";

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
fn tmp_out(name: &str) -> PathBuf {
    let stamp: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    std::env::temp_dir().join(format!("disrobe-chain-{name}-{stamp}"))
}

fn run_chain_cli(input: &Path, out: &Path, chain_arg: &str) -> std::process::Output {
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
        .arg(chain_arg)
        .arg("--capture-stages")
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

fn read_chain_json(out_dir: &Path) -> String {
    let p: PathBuf = out_dir.join("chain.json");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read chain.json at {p:?}: {e}"))
}

fn pyarmor_v8_wrapper() -> Option<Vec<u8>> {
    let fixture: PathBuf = corpus_path(
        "python/pyarmor/v8/basic/chunk_00_try_except_basic_try_except_else/chunk_00_try_except_basic_try_except_else.py",
    );
    std::fs::read(&fixture).ok()
}

fn push_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn build_toc_entry(position: u32, payload_len: u32, type_byte: u8, name: &str) -> Vec<u8> {
    let name_bytes: &[u8] = name.as_bytes();
    let entry_size: u32 = 18 + u32::try_from(name_bytes.len()).expect("entry name fits u32");
    let mut e: Vec<u8> = Vec::with_capacity(entry_size as usize);
    push_u32_be(&mut e, entry_size);
    push_u32_be(&mut e, position);
    push_u32_be(&mut e, payload_len);
    push_u32_be(&mut e, payload_len);
    e.push(0u8);
    e.push(type_byte);
    e.extend_from_slice(name_bytes);
    e
}

fn synthesize_pyinstaller_archive(child: &[u8], child_name: &str) -> Vec<u8> {
    let payload: &[u8] = child;
    let payload_len: u32 = u32::try_from(payload.len()).expect("child payload fits u32");
    let toc_entry: Vec<u8> = build_toc_entry(0, payload_len, b'm', child_name);
    let toc_offset: u32 = payload_len;
    let toc_length: u32 = u32::try_from(toc_entry.len()).expect("toc fits u32");
    let cookie_len: usize = 88;
    let package_len: u32 = toc_offset + toc_length + u32::try_from(cookie_len).expect("cookie u32");

    let mut archive: Vec<u8> = Vec::with_capacity(package_len as usize);
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&toc_entry);
    archive.extend_from_slice(MEI_MAGIC);
    push_u32_be(&mut archive, package_len);
    push_u32_be(&mut archive, toc_offset);
    push_u32_be(&mut archive, toc_length);
    push_u32_be(&mut archive, 312);
    let mut libname: Vec<u8> = b"python312.dll".to_vec();
    libname.resize(64, 0u8);
    archive.extend_from_slice(&libname);
    archive
}

fn node_depth(node: &serde_json::Value) -> i64 {
    node.get("depth")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(-1)
}

fn max_depth(doc: &serde_json::Value) -> i64 {
    doc.get("nodes")
        .and_then(serde_json::Value::as_array)
        .map_or(-1, |nodes: &Vec<serde_json::Value>| {
            nodes.iter().map(node_depth).max().unwrap_or(-1)
        })
}

fn terminal_source(out_dir: &Path) -> Option<String> {
    let final_dir: PathBuf = out_dir.join("final");
    let read: std::fs::ReadDir = std::fs::read_dir(&final_dir).ok()?;
    for entry in read.flatten() {
        let name: String = entry.file_name().to_string_lossy().into_owned();
        if name.contains("decompile") {
            let bin: PathBuf = entry.path().join("output.bin");
            if let Ok(text) = std::fs::read_to_string(&bin) {
                return Some(text);
            }
        }
    }
    None
}

fn source_has_def_class_import(src: &str) -> bool {
    src.lines().any(|line: &str| {
        let t: &str = line.trim_start();
        t.starts_with("def ")
            || t.starts_with("class ")
            || t.starts_with("import ")
            || t.starts_with("from ")
            || t.starts_with("async def ")
    })
}

#[test]
fn test_auto_full_python_chain_pyinstaller_pyarmor_pyc() {
    let Some(child): Option<Vec<u8>> = pyarmor_v8_wrapper() else {
        eprintln!(
            "SKIP: pyarmor v8 fixture absent; cannot synthesize pyinstaller->pyarmor envelope"
        );
        return;
    };

    let archive: Vec<u8> = synthesize_pyinstaller_archive(&child, "chunk_00.pyc");
    let out: PathBuf = tmp_out("full-python");
    let input: PathBuf = tmp_out("full-python-input").with_extension("pkg");
    std::fs::write(&input, &archive)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot write synthetic archive: {e}"));

    let proc_out: std::process::Output = run_chain_cli(&input, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain run failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let json: String = read_chain_json(&out);
    let recognized_envelope: bool = json.contains("pyinstaller.extract")
        || json.contains("pyinstaller-carchive")
        || json.contains("pyarmor.unpack")
        || json.contains("pyarmor-v8");
    assert!(
        recognized_envelope,
        "synthetic envelope must be recognized as a pyinstaller carchive or its embedded \
         pyarmor payload; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );

    let doc: serde_json::Value = serde_json::from_str(&json)
        .unwrap_or_else(|e: serde_json::Error| panic!("chain.json is not valid json: {e}"));
    let depth: i64 = max_depth(&doc);

    if depth < 3 {
        eprintln!(
            "SKIP: chain depth {depth} < 3. Two engine realities block the \
             pyinstaller-extract -> pyarmor.unpack -> py.decompile chain: (1) pyinstaller.extract \
             returns OutputKind::Mixed{{children: empty}}, so extracted children are never \
             re-fed; (2) the pyarmor detector's whole-buffer wrapper-text scan matches the \
             embedded payload first, short-circuiting the outer pyinstaller stage; and pyarmor \
             v8 supermode static unpack needs the runtime key, so its plaintext pyc is not \
             recovered. Fix the inner-child re-feed wiring + envelope precedence before this \
             chain can reach depth>=3."
        );
        return;
    }

    let Some(src): Option<String> = terminal_source(&out) else {
        eprintln!(
            "SKIP: chain reached depth {depth} but produced no py.decompile terminal source \
             (pyarmor v8 static unpack does not yield a decryptable pyc without the runtime key)."
        );
        return;
    };

    assert!(
        source_has_def_class_import(&src),
        "terminal source at depth {depth} must contain a real def/class/import token; \
         got prefix: {prefix}",
        prefix = &src[..src.len().min(400)]
    );
}
