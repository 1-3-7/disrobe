#![cfg(feature = "js")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use common::{run_disrobe, temp_dir, temp_path, write_bytes};

const fn align_up(value: usize, align: usize) -> usize {
    let rem: usize = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
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
    let header_size: u32 = u32::try_from(header_bytes.len()).unwrap();
    let aligned: u32 = u32::try_from(align_up(header_bytes.len(), 4)).unwrap();
    let pickle_size: u32 = 8 + aligned;
    let outer: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&outer);
    out.extend_from_slice(&pickle_size.to_le_bytes());
    out.extend_from_slice(&outer);
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(header_bytes);
    out.extend(std::iter::repeat_n(0u8, (aligned - header_size) as usize));
    for (_, body) in files {
        out.extend_from_slice(body);
    }
    out
}

const NEXE_FOOTER_MAGIC: &[u8] = b"<nexe~~sentinel>";

fn synth_nexe(code: &[u8], resources: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0u8; 256];
    out.extend_from_slice(code);
    out.extend_from_slice(resources);
    out.extend_from_slice(&(code.len() as u64).to_le_bytes());
    out.extend_from_slice(&(resources.len() as u64).to_le_bytes());
    out.extend_from_slice(NEXE_FOOTER_MAGIC);
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask: u32 = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn synth_stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let mut local_offsets: Vec<u32> = Vec::new();
    for (name, body) in files {
        let name_bytes: &[u8] = name.as_bytes();
        let crc: u32 = crc32(body);
        let size: u32 = u32::try_from(body.len()).unwrap();
        local_offsets.push(u32::try_from(out.len()).unwrap());
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&u16::try_from(name_bytes.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(body);
    }
    let central_start: u32 = u32::try_from(out.len()).unwrap();
    for (i, (name, body)) in files.iter().enumerate() {
        let name_bytes: &[u8] = name.as_bytes();
        let crc: u32 = crc32(body);
        let size: u32 = u32::try_from(body.len()).unwrap();
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&u16::try_from(name_bytes.len()).unwrap().to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_offsets[i].to_le_bytes());
        central.extend_from_slice(name_bytes);
    }
    let central_size: u32 = u32::try_from(central.len()).unwrap();
    let count: u16 = u16::try_from(files.len()).unwrap();
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn synth_nwjs_binary(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = b"MZ\x00\x00host-executable-prefix\x00\x00".to_vec();
    out.extend_from_slice(&synth_stored_zip(files));
    out
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

#[test]
fn v8_out_carves_asar_members_to_disk() {
    let (_input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("asar", "asar");
    let bytes: Vec<u8> = synth_asar(&[
        ("renderer.js", b"console.log('renderer')"),
        (
            "nested/preload.js",
            b"contextBridge.exposeInMainWorld('x', {})",
        ),
    ]);
    write_bytes(&input, &bytes);
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("asar-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let run: common::Run = run_disrobe(&[
        "js",
        "v8",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "asar carve failed: {}", run.stderr);

    let renderer: PathBuf = out.join("renderer.js");
    let preload: PathBuf = out.join("nested/preload.js");
    assert!(
        renderer.exists(),
        "renderer.js not carved; stdout:\n{}",
        run.stdout
    );
    assert!(
        preload.exists(),
        "nested/preload.js not carved; stdout:\n{}",
        run.stdout
    );
    assert_eq!(read(&renderer), b"console.log('renderer')");
    assert_eq!(read(&preload), b"contextBridge.exposeInMainWorld('x', {})");
}

#[test]
fn v8_out_carves_nexe_payload_to_disk() {
    let (_input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("nexe", "exe");
    let code: &[u8] = b"// nexe bundled entry\nmodule.exports = 1;\n";
    let resources: &[u8] = b"{\"asset\":true}";
    write_bytes(&input, &synth_nexe(code, resources));
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("nexe-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let run: common::Run = run_disrobe(&[
        "js",
        "v8",
        input.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "nexe carve failed: {}", run.stderr);

    let payload: PathBuf = out.join("nexe-payload.bin");
    assert!(
        payload.exists(),
        "nexe payload not carved; stdout:\n{}",
        run.stdout
    );
    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(code);
    expected.extend_from_slice(resources);
    assert_eq!(read(&payload), expected);
}

#[test]
fn v8_out_carves_nwjs_zip_members_to_disk() {
    let (_input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("nwjs", "exe");
    write_bytes(
        &input,
        &synth_nwjs_binary(&[
            ("app.js", b"window.nw = require('nw.gui');"),
            ("package.json", b"{\"main\":\"app.js\"}"),
        ]),
    );
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("nwjs-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let run: common::Run = run_disrobe(&[
        "js",
        "v8",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "nwjs carve failed: {}", run.stderr);

    let app: PathBuf = out.join("app.js");
    let pkg: PathBuf = out.join("package.json");
    assert!(app.exists(), "app.js not carved; stdout:\n{}", run.stdout);
    assert!(
        pkg.exists(),
        "package.json not carved; stdout:\n{}",
        run.stdout
    );
    assert_eq!(read(&app), b"window.nw = require('nw.gui');");
    assert_eq!(read(&pkg), b"{\"main\":\"app.js\"}");
}

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

#[test]
fn v8_out_carves_real_sea_main_code_to_disk() {
    let blob: PathBuf = workspace_root().join("corpus/js/sea/sea-prep.blob");
    assert!(
        blob.exists(),
        "{} is tracked in git and this case grades nothing without it, so its absence is a \
         damaged checkout rather than an optional dependency",
        blob.display()
    );
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("sea-out");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let run: common::Run = run_disrobe(&[
        "js",
        "v8",
        blob.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "sea carve failed: {}", run.stderr);

    let entries: Vec<PathBuf> = std::fs::read_dir(&out)
        .expect("read sea out dir")
        .filter_map(|e: std::io::Result<std::fs::DirEntry>| e.ok().map(|d| d.path()))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one carved sea member, got {entries:?}"
    );
    let carved: &PathBuf = &entries[0];
    let body: Vec<u8> = read(carved);
    assert!(!body.is_empty(), "carved sea main code is empty");
    let text: String = String::from_utf8_lossy(&body).into_owned();
    assert!(
        text.contains("console.log") || text.contains("require"),
        "carved sea main code looks like garbage: {text:?}"
    );
}
