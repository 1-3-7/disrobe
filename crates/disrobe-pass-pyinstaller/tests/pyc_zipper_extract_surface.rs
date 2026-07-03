#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unreadable_literal
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_pyinstaller::{
    ExtractOutput, ExtractedEntry, ProtectionSignal, PyInstallerManifest, ZipperCompression,
    build_manifest, extract_archive,
};

const MEI_MAGIC: &[u8; 8] = b"MEI\x0C\x0B\x0A\x0B\x0E";
const COOKIE_LEN_V21: usize = 88;
const PY314_PYC_HEADER_LEN: usize = 16;
const PY314_VER: u32 = 314;

const PACKED_ZLIB: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyc_zipper/packed_zlib.pyc.bin");
const ORIGINAL_PYC: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyc_zipper/original.pyc.bin");

fn zlib_compress(input: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write as _;
    let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::new(9));
    enc.write_all(input).expect("zlib write");
    enc.finish().expect("zlib finish")
}

fn push_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn assemble_zipped_module_carchive() -> Vec<u8> {
    let module_marshal: &[u8] = &PACKED_ZLIB[PY314_PYC_HEADER_LEN..];
    let compressed: Vec<u8> = zlib_compress(module_marshal);

    let mut data_region: Vec<u8> = Vec::new();
    let mut toc_region: Vec<u8> = Vec::new();

    let position: u32 = 0u32;
    let compressed_len: u32 = u32::try_from(compressed.len()).expect("clen fits u32");
    let uncompressed_len: u32 = u32::try_from(module_marshal.len()).expect("ulen fits u32");
    data_region.extend_from_slice(&compressed);

    let name: &str = "zipped_module";
    let name_bytes: &[u8] = name.as_bytes();
    let entry_size: u32 = 18 + u32::try_from(name_bytes.len()).expect("name fits u32");
    push_u32_be(&mut toc_region, entry_size);
    push_u32_be(&mut toc_region, position);
    push_u32_be(&mut toc_region, compressed_len);
    push_u32_be(&mut toc_region, uncompressed_len);
    toc_region.push(1u8);
    toc_region.push(b'm');
    toc_region.extend_from_slice(name_bytes);

    let toc_offset: u32 = u32::try_from(data_region.len()).expect("toc_offset fits u32");
    let toc_length: u32 = u32::try_from(toc_region.len()).expect("toc_length fits u32");
    let package_len: u32 =
        toc_offset + toc_length + u32::try_from(COOKIE_LEN_V21).expect("cookie len fits u32");

    let mut archive: Vec<u8> = Vec::with_capacity(package_len as usize);
    archive.extend_from_slice(&data_region);
    archive.extend_from_slice(&toc_region);
    archive.extend_from_slice(MEI_MAGIC);
    push_u32_be(&mut archive, package_len);
    push_u32_be(&mut archive, toc_offset);
    push_u32_be(&mut archive, toc_length);
    push_u32_be(&mut archive, PY314_VER);
    let mut libname: Vec<u8> = b"python314.dll".to_vec();
    libname.resize(64, 0u8);
    archive.extend_from_slice(&libname);
    archive
}

#[test]
fn extract_peels_pyc_zipper_module_back_to_original_bytes() {
    let archive: Vec<u8> = assemble_zipped_module_carchive();
    let output: ExtractOutput =
        extract_archive(&archive).expect("pyc-zipper-wrapped carchive must extract");

    assert_eq!(
        output.pyc_unzipped_count, 1,
        "the single zlib pyc-zipper module must be peeled exactly once"
    );

    let module: &ExtractedEntry = output
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| e.toc.name == "zipped_module")
        .expect("zipped module survives extraction");
    assert!(
        module.pyc_unzipped,
        "the module entry must be flagged as pyc-zipper-unwrapped"
    );
    assert_eq!(
        module.pyc_compression,
        Some(ZipperCompression::Zlib),
        "the recorded compression scheme must be zlib for this fixture"
    );
    assert_eq!(
        module.data, ORIGINAL_PYC,
        "the recovered .pyc bytes must equal the committed pre-zip original.pyc"
    );
}

#[test]
fn manifest_surfaces_pyc_zipper_recovery() {
    let archive: Vec<u8> = assemble_zipped_module_carchive();
    let output: ExtractOutput = extract_archive(&archive).expect("extract");
    let manifest: PyInstallerManifest = build_manifest(&archive, &output);

    assert_eq!(
        manifest.pyc_unzipped_count, 1,
        "manifest must carry the pyc-unzipped count"
    );
    assert!(
        manifest
            .protection
            .signals
            .contains(&ProtectionSignal::PycZipperRecompressed),
        "manifest protection report must raise the pyc-zipper-recompressed signal"
    );
    assert!(
        manifest
            .protection
            .notes
            .iter()
            .any(|n: &String| n.contains("pyc-zipper")),
        "manifest protection notes must explain the pyc-zipper peel"
    );

    let module_index: usize = manifest
        .entries
        .iter()
        .position(|e| e.name == "zipped_module")
        .expect("module present in manifest");
    assert!(
        manifest.entries[module_index].pyc_unzipped,
        "manifest entry must flag the unzipped module"
    );
    assert_eq!(
        manifest.entries[module_index].pyc_compression.as_deref(),
        Some("zlib"),
        "manifest entry must record the zlib compression scheme label"
    );
}

fn workspace_target_dir() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set under cargo test");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("target");
    p
}

fn locate_disrobe_cli() -> Option<PathBuf> {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let target: PathBuf = workspace_target_dir();
    for profile in ["debug", "release"] {
        let candidate: PathBuf = target.join(profile).join(exe_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn cli_extract_json_manifest_reports_pyc_zipper_decompression() {
    let Some(cli): Option<PathBuf> = locate_disrobe_cli() else {
        eprintln!(
            "SKIP: built `disrobe` CLI not found under target/{{debug,release}}; run `cargo build -p disrobe-cli` first to exercise the user-facing extract surface"
        );
        return;
    };

    let archive: Vec<u8> = assemble_zipped_module_carchive();
    let tmp: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-pyc-zipper-{}-{}",
        std::process::id(),
        archive.len()
    ));
    std::fs::create_dir_all(&tmp).expect("create scratch dir");
    let input: PathBuf = tmp.join("zipped_app.bin");
    let out_dir: PathBuf = tmp.join("extracted");
    std::fs::write(&input, &archive).expect("write carchive fixture");

    let output: std::process::Output = Command::new(&cli)
        .arg("pyinstaller")
        .arg("extract")
        .arg(&input)
        .arg("--out")
        .arg(&out_dir)
        .arg("--force")
        .output()
        .expect("spawn the built disrobe cli");

    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "disrobe pyinstaller extract must succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("pyc-unzipped: 1"),
        "human-readable extract output must report the unzipped count; got:\n{stdout}"
    );

    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest_text: String =
        std::fs::read_to_string(&manifest_path).expect("manifest.json must be written");
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_text).expect("manifest.json must be valid json");

    assert_eq!(
        manifest
            .get("pyc_unzipped_count")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "the extract --json manifest must surface pyc_unzipped_count=1; manifest:\n{manifest_text}"
    );

    let entries: &Vec<serde_json::Value> = manifest
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .expect("manifest carries an entries array");
    let module: &serde_json::Value = entries
        .iter()
        .find(|e: &&serde_json::Value| {
            e.get("name").and_then(serde_json::Value::as_str) == Some("zipped_module")
        })
        .expect("zipped_module entry present in the json manifest");
    assert_eq!(
        module
            .get("pyc_unzipped")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "the json manifest entry must flag pyc_unzipped=true"
    );
    assert_eq!(
        module
            .get("pyc_compression")
            .and_then(serde_json::Value::as_str),
        Some("zlib"),
        "the json manifest entry must record the zlib decompression scheme"
    );

    let recovered: Vec<u8> =
        std::fs::read(out_dir.join("zipped_module.pyc")).expect("recovered .pyc written to disk");
    assert_eq!(
        recovered, ORIGINAL_PYC,
        "the .pyc written under the extract dir must be the peeled original bytes"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
