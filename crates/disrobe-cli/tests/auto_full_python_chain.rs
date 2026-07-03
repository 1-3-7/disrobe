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
    let pid: u32 = std::process::id();
    std::env::temp_dir().join(format!("disrobe-chain-{name}-{pid}-{stamp}"))
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

fn pyc_3_11_body() -> Option<Vec<u8>> {
    let fixture: PathBuf = corpus_path("python/decompile/legacy/compiled/binary_ops.3.11.pyc");
    let raw: Vec<u8> = std::fs::read(&fixture).ok()?;
    if raw.len() <= 16 {
        return None;
    }
    Some(raw[16..].to_vec())
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

fn synthesize_pyinstaller_archive(child: &[u8], child_name: &str, py_minor: u8) -> Vec<u8> {
    let payload: &[u8] = child;
    let payload_len: u32 = u32::try_from(payload.len()).expect("child payload fits u32");
    let toc_entry: Vec<u8> = build_toc_entry(0, payload_len, b'm', child_name);
    let toc_offset: u32 = payload_len;
    let toc_length: u32 = u32::try_from(toc_entry.len()).expect("toc fits u32");
    let cookie_len: usize = 88;
    let package_len: u32 = toc_offset + toc_length + u32::try_from(cookie_len).expect("cookie u32");
    let pyvers: u32 = 300 + u32::from(py_minor);

    let mut archive: Vec<u8> = Vec::with_capacity(package_len as usize);
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&toc_entry);
    archive.extend_from_slice(MEI_MAGIC);
    push_u32_be(&mut archive, package_len);
    push_u32_be(&mut archive, toc_offset);
    push_u32_be(&mut archive, toc_length);
    push_u32_be(&mut archive, pyvers);
    let mut libname: Vec<u8> = format!("python3{py_minor}.dll").into_bytes();
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

fn picked_format_tags(doc: &serde_json::Value) -> Vec<String> {
    doc.get("nodes")
        .and_then(serde_json::Value::as_array)
        .map(|nodes: &Vec<serde_json::Value>| {
            nodes
                .iter()
                .filter_map(|n: &serde_json::Value| {
                    n.get("format_tag_in")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
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

fn terminal_decompile_source(out_dir: &Path) -> Option<String> {
    let read: std::fs::ReadDir = std::fs::read_dir(out_dir).ok()?;
    for entry in read.flatten() {
        let name: String = entry.file_name().to_string_lossy().into_owned();
        if name.contains("decompile") && entry.path().is_dir() {
            let bin: PathBuf = entry.path().join("output.bin");
            if let Ok(text) = std::fs::read_to_string(&bin) {
                return Some(text);
            }
        }
    }
    None
}

fn source_has_def_class_import_or_print(src: &str) -> bool {
    src.lines().any(|line: &str| {
        let t: &str = line.trim_start();
        t.starts_with("def ")
            || t.starts_with("class ")
            || t.starts_with("import ")
            || t.starts_with("from ")
            || t.starts_with("async def ")
            || t.starts_with("print(")
    })
}

#[test]
fn test_auto_full_python_chain_pyinstaller_pyc_decompile() {
    let Some(pyc_body): Option<Vec<u8>> = pyc_3_11_body() else {
        eprintln!(
            "SKIP: binary_ops.3.11.pyc fixture absent; cannot synthesize pyinstaller envelope"
        );
        return;
    };

    let archive: Vec<u8> = synthesize_pyinstaller_archive(&pyc_body, "binary_ops", 11);
    let out: PathBuf = tmp_out("full-python-pyc");
    let input: PathBuf = tmp_out("full-python-pyc-input").with_extension("pkg");
    std::fs::write(&input, &archive)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot write synthetic archive: {e}"));

    let proc_out: std::process::Output = run_chain_cli(&input, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain run failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let json: String = read_chain_json(&out);
    let doc: serde_json::Value = serde_json::from_str(&json)
        .unwrap_or_else(|e: serde_json::Error| panic!("chain.json is not valid json: {e}"));
    let depth: i64 = max_depth(&doc);
    let passes: Vec<String> = picked_passes(&doc);

    assert!(
        passes.iter().any(|p: &String| p == "pyinstaller.extract"),
        "depth-1 must peel the pyinstaller carchive before the inner pyc; passes: {passes:?}"
    );
    assert!(
        passes.iter().any(|p: &String| p == "py.decompile"),
        "the inner pyc child must be re-fed to py.decompile (inner-child re-feed); passes: {passes:?}"
    );
    assert!(
        depth >= 2,
        "pyinstaller->pyc->decompile must reach depth>=2 via inner-child re-feed; got {depth}"
    );

    let src: String = terminal_decompile_source(&out).unwrap_or_else(|| {
        panic!(
            "no py.decompile terminal output.bin; the inner-child re-feed must deliver the \
             extracted pyc body to py.decompile and recover real source"
        )
    });
    assert!(
        source_has_def_class_import_or_print(&src),
        "terminal source must contain a real python statement recovered from the embedded pyc; \
         got prefix: {prefix}",
        prefix = &src[..src.len().min(400)]
    );
    assert!(
        src.contains('+') && src.contains('a') && src.contains('b'),
        "recovered source must reflect the binary_ops.3.11 body (a/b arithmetic), proving a \
         non-circular decode rather than an echo of the archive; got prefix: {prefix}",
        prefix = &src[..src.len().min(200)]
    );

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn test_auto_full_python_chain_pyinstaller_pyarmor_advances_to_pyarmor_stage() {
    let Some(child): Option<Vec<u8>> = pyarmor_v8_wrapper() else {
        eprintln!(
            "SKIP: pyarmor v8 fixture absent; cannot synthesize pyinstaller->pyarmor envelope"
        );
        return;
    };

    let archive: Vec<u8> = synthesize_pyinstaller_archive(&child, "chunk_00", 11);
    let out: PathBuf = tmp_out("full-python-pyarmor");
    let input: PathBuf = tmp_out("full-python-pyarmor-input").with_extension("pkg");
    std::fs::write(&input, &archive)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot write synthetic archive: {e}"));

    let proc_out: std::process::Output = run_chain_cli(&input, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain run failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let json: String = read_chain_json(&out);
    let doc: serde_json::Value = serde_json::from_str(&json)
        .unwrap_or_else(|e: serde_json::Error| panic!("chain.json is not valid json: {e}"));
    let depth: i64 = max_depth(&doc);
    let passes: Vec<String> = picked_passes(&doc);
    let tags: Vec<String> = picked_format_tags(&doc);

    assert!(
        passes.iter().any(|p: &String| p == "pyinstaller.extract"),
        "the outer pyinstaller carchive must be peeled first (its validated MEI cookie outranks \
         the pyarmor wrapper bytes embedded inside the still-packed archive); passes: {passes:?}"
    );
    assert!(
        passes.iter().any(|p: &String| p == "pyarmor.unpack")
            && tags.iter().any(|t: &String| t.starts_with("pyarmor")),
        "the extracted pyarmor child must be re-fed to pyarmor.unpack at the next depth, proving \
         the inner-child re-feed advanced past the depth-1 stall; passes: {passes:?} tags: {tags:?}"
    );
    assert!(
        depth >= 2,
        "pyinstaller->pyarmor must reach depth>=2 (no longer a depth-1 stall); got {depth}"
    );

    let pyarmor_terminal: Option<String> = terminal_decompile_source(&out);
    if let Some(src) = pyarmor_terminal.as_deref() {
        assert!(
            source_has_def_class_import_or_print(src),
            "pyarmor v8 supermode is a runtime-key wall (the protected pyc cannot be statically \
             decrypted without the per-process key, absent from the static wrapper), so this chain \
             is expected to reach the pyarmor stage and wall there rather than emit a terminal; if \
             a terminal source ever is produced it must be real python, not a fabricated echo; \
             got prefix: {prefix}",
            prefix = &src[..src.len().min(400)]
        );
    }

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_dir_all(&out);
}
