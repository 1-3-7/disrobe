#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_binfmt::asar::{AsarEntry, AsarLayout};

const KNOWN_IDENTIFIER: &str = "electronSecretToken";
const ENTRY_NAME: &str = "index.js";
const ASAR_ALIGNMENT_PREFIX: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

fn cargo_bin() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

#[allow(clippy::disallowed_methods)]
fn tmp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-electron-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn run_chain_cli_capture(input: &Path, out: &Path) -> std::process::Output {
    let bin: PathBuf = cargo_bin();
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

fn obfuscated_index_js() -> Vec<u8> {
    let mut src: String = String::new();
    let _: core::fmt::Result = write!(
        src,
        "var _0x1a2b=['{KNOWN_IDENTIFIER}'];var _0x3c4d=function(){{return _0x1a2b[0x0];}};\
console[_0x1a2b[0x0]];var _0x5e6f=function(_0x11){{return _0x11;}};module['exports']=_0x3c4d;"
    );
    src.into_bytes()
}

fn synth_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut header: String = String::from(r#"{"files":{"#);
    let mut offset: u64 = 0;
    for (i, (name, body)) in files.iter().enumerate() {
        if i > 0 {
            header.push(',');
        }
        let size: usize = body.len();
        let _: core::fmt::Result =
            write!(header, r#""{name}":{{"size":{size},"offset":"{offset}"}}"#);
        offset += body.len() as u64;
    }
    header.push_str("}}");
    let header_bytes: &[u8] = header.as_bytes();
    let header_size: u32 = u32::try_from(header_bytes.len()).expect("header size fits u32");
    let aligned_size: usize = (header_bytes.len() + 3) & !3;
    let aligned: u32 = u32::try_from(aligned_size).expect("aligned size fits u32");
    let string_pickle_size: u32 = aligned + 4;
    let header_pickle_size: u32 = string_pickle_size + 4;
    let payload_total: usize = usize::try_from(offset).expect("payload total fits usize");
    let mut out: Vec<u8> = Vec::with_capacity(16 + aligned_size + payload_total);
    out.extend_from_slice(&ASAR_ALIGNMENT_PREFIX);
    out.extend_from_slice(&header_pickle_size.to_le_bytes());
    out.extend_from_slice(&string_pickle_size.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(header_bytes);
    let padding: usize = (aligned - header_size) as usize;
    out.extend(std::iter::repeat_n(0u8, padding));
    for (_, body) in files {
        out.extend_from_slice(body);
    }
    out
}

#[test]
fn auto_electron_asar_unpack_then_js_deob_recovers_identifier() {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing \
         {} would leave this case driving nothing",
        bin.display()
    );

    let index_js: Vec<u8> = obfuscated_index_js();
    let package_json: &[u8] =
        br#"{"name":"demo-electron-app","version":"1.0.0","main":"index.js"}"#;
    let asar_bytes: Vec<u8> =
        synth_asar(&[(ENTRY_NAME, &index_js), ("package.json", package_json)]);

    let asar_dir_scratch: disrobe_core::scratch::ScratchDir = tmp_dir("asar");

    let asar_dir: PathBuf = asar_dir_scratch.path().to_path_buf();
    std::fs::create_dir_all(&asar_dir).expect("create asar tmp dir");
    let asar_path: PathBuf = asar_dir.join("hello.asar");
    std::fs::write(&asar_path, &asar_bytes).expect("write hello.asar");

    let asar_out_scratch: disrobe_core::scratch::ScratchDir = tmp_dir("asar-out");

    let asar_out: PathBuf = asar_out_scratch.path().to_path_buf();
    let asar_proc: std::process::Output = run_chain_cli_capture(&asar_path, &asar_out);
    assert!(
        asar_proc.status.success(),
        "asar chain failed: {}",
        String::from_utf8_lossy(&asar_proc.stderr)
    );
    let asar_json: String = read_chain_json(&asar_out);
    let binfmt_route: bool = asar_json.contains("\"pass\": \"binfmt.container\"")
        && asar_json.contains("\"format_tag_in\": \"asar\"");
    let webview_route: bool = asar_json.contains("\"pass\": \"webview.carve\"")
        && asar_json.contains("\"format_tag_in\": \"electron-asar\"");
    assert!(
        binfmt_route || webview_route,
        "chain.json must show the registered extractor that owns the asar input; got prefix: {prefix}",
        prefix = &asar_json[..asar_json.len().min(700)]
    );

    let layout: AsarLayout =
        disrobe_binfmt::asar::parse(&asar_bytes).expect("synthesized asar must parse");
    let index_entry: &AsarEntry = layout
        .entries
        .iter()
        .find(|e: &&AsarEntry| e.path == ENTRY_NAME)
        .expect("asar unpack must recover the index.js entry");
    let extracted: &[u8] = disrobe_binfmt::asar::read_entry(&asar_bytes, &layout, index_entry)
        .expect("asar read_entry must return the bundled JavaScript");
    assert_eq!(
        extracted, index_js,
        "extracted index.js must be byte-identical to the bundled obfuscated source"
    );

    let js_dir_scratch: disrobe_core::scratch::ScratchDir = tmp_dir("js");

    let js_dir: PathBuf = js_dir_scratch.path().to_path_buf();
    std::fs::create_dir_all(&js_dir).expect("create js tmp dir");
    let js_path: PathBuf = js_dir.join(ENTRY_NAME);
    std::fs::write(&js_path, extracted).expect("write extracted index.js");

    let js_out_scratch: disrobe_core::scratch::ScratchDir = tmp_dir("js-out");

    let js_out: PathBuf = js_out_scratch.path().to_path_buf();
    let js_proc: std::process::Output = run_chain_cli_capture(&js_path, &js_out);
    assert!(
        js_proc.status.success(),
        "js.deob chain failed: {}",
        String::from_utf8_lossy(&js_proc.stderr)
    );
    let js_json: String = read_chain_json(&js_out);
    assert!(
        js_json.contains("\"pass\": \"js.deob\""),
        "chain.json must show the js.deob pass on the unpacked source; got prefix: {prefix}",
        prefix = &js_json[..js_json.len().min(700)]
    );

    let terminal: Vec<u8> = read_terminal_stage(&js_out);
    let terminal_text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&terminal);
    assert!(
        terminal_text.contains(KNOWN_IDENTIFIER),
        "js.deob auto output must recover the known identifier {KNOWN_IDENTIFIER:?}"
    );
}

fn read_terminal_stage(out_dir: &Path) -> Vec<u8> {
    let mut combined: Vec<u8> = Vec::new();
    collect_files(out_dir, &mut combined);
    assert!(
        !combined.is_empty(),
        "auto output dir {out_dir:?} must contain recovered artifacts"
    );
    combined
}

fn collect_files(dir: &Path, out: &mut Vec<u8>) {
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(std::io::Result::ok) {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.extend_from_slice(&bytes);
            out.push(b'\n');
        }
    }
}
