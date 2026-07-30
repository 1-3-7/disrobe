#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::extract::{ExtractedEntry, ExtractionResult, extract_to};

use common::requirement::{WIX, find_on_path, unmeasured};

fn find_wix() -> Option<PathBuf> {
    if let Some(found) = find_on_path("wix") {
        return Some(found);
    }
    if cfg!(windows) {
        for root in [
            r"C:\Program Files\WiX Toolset v7.0\bin\wix.exe",
            r"C:\Program Files\WiX Toolset v6.0\bin\wix.exe",
            r"C:\Program Files (x86)\WiX Toolset v7.0\bin\wix.exe",
        ] {
            let candidate: PathBuf = PathBuf::from(root);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn seed_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut text: Vec<u8> = Vec::new();
    for _ in 0..40 {
        text.extend_from_slice(b"hello disrobe msi embedded cabinet round trip\n");
    }
    let mut prose: Vec<u8> = Vec::new();
    for _ in 0..70 {
        prose.extend_from_slice(b"the quick brown fox jumps over the lazy dog 0123456789\n");
    }
    let mut binary: Vec<u8> = Vec::with_capacity(4096);
    for i in 0..4096u32 {
        binary.push((i.wrapping_mul(40503).rotate_left(5) & 0xff) as u8);
    }
    let files: Vec<(String, Vec<u8>)> = vec![
        ("alpha.txt".to_owned(), text),
        ("beta.txt".to_owned(), prose),
        ("gamma.bin".to_owned(), binary),
    ];
    std::fs::create_dir_all(dir).expect("mk seed dir");
    for (name, body) in &files {
        std::fs::write(dir.join(name), body).expect("write seed");
    }
    files
}

fn build_msi(wix: &Path, seed_dir: &Path, out_dir: &Path) -> Option<PathBuf> {
    std::fs::create_dir_all(out_dir).expect("mk out dir");
    let mut wxs: String = String::new();
    wxs.push_str("<Wix xmlns=\"http://wixtoolset.org/schemas/v4/wxs\">\n");
    push_line(
        &mut wxs,
        "  <Package Name=\"DisrobeMsiProof\" Manufacturer=\"Latency LLC\" Version=\"1.0.0.0\" UpgradeCode=\"11111111-2222-3333-4444-555555555555\" Compressed=\"yes\">",
    );
    wxs.push_str("    <MediaTemplate EmbedCab=\"yes\" CompressionLevel=\"high\" />\n");
    wxs.push_str("    <StandardDirectory Id=\"ProgramFilesFolder\">\n");
    wxs.push_str("      <Directory Id=\"INSTALLDIR\" Name=\"DisrobeMsiProof\">\n");
    for (idx, name) in ["alpha.txt", "beta.txt", "gamma.bin"].iter().enumerate() {
        push_line(
            &mut wxs,
            &format!(
                "        <Component Id=\"Cmp{idx}\" Guid=\"*\"><File Id=\"F{idx}\" Source=\"{}\" KeyPath=\"yes\" /></Component>",
                seed_dir.join(name).display()
            ),
        );
    }
    wxs.push_str("      </Directory>\n    </StandardDirectory>\n");
    wxs.push_str("    <Feature Id=\"Main\">\n");
    for idx in 0..3 {
        push_line(&mut wxs, &format!("      <ComponentRef Id=\"Cmp{idx}\" />"));
    }
    wxs.push_str("    </Feature>\n  </Package>\n</Wix>\n");
    let wxs_path: PathBuf = out_dir.join("proof.wxs");
    std::fs::write(&wxs_path, wxs).expect("write wxs");
    let msi_path: PathBuf = out_dir.join("proof.msi");
    let Ok(status) = Command::new(wix)
        .arg("build")
        .arg(&wxs_path)
        .arg("-o")
        .arg(&msi_path)
        .current_dir(out_dir)
        .status()
    else {
        return None;
    };
    if !status.success() {
        return None;
    }
    msi_path.is_file().then_some(msi_path)
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

#[test]
fn real_msi_embedded_cab_round_trips() {
    let Some(wix): Option<PathBuf> = find_wix() else {
        unmeasured(
            &WIX,
            "byte-exact recovery of the cabinet embedded in an installer built by the \
             real WiX toolset",
            "no wix binary is on PATH or in the standard install directories",
        );
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_msi_seed")
            .expect("create scratch directory");
    let seed_dir: PathBuf = scratch.path().join("seed");
    let out_dir: PathBuf = scratch.path().join("build");
    let originals: Vec<(String, Vec<u8>)> = seed_files(&seed_dir);
    let Some(msi): Option<PathBuf> = build_msi(&wix, &seed_dir, &out_dir) else {
        panic!("wix failed to build msi");
    };
    let bytes: Vec<u8> = std::fs::read(&msi).expect("read msi");

    let summary: disrobe_binfmt::containers::msi::MsiSummary =
        disrobe_binfmt::containers::msi::parse_msi_minimal(&bytes).expect("parse msi summary");
    assert!(summary.tables.iter().any(|t: &String| t == "File"));
    assert!(summary.tables.iter().any(|t: &String| t == "Media"));

    let extract_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_msi_extract")
            .expect("create scratch directory");
    let extract_out: PathBuf = extract_scratch.path().join("out");
    let result: ExtractionResult =
        extract_to(ContainerKind::Msi, &bytes, &extract_out).expect("extract msi");
    assert_eq!(result.kind, ContainerKind::Msi);

    for (name, body) in &originals {
        let entry: &ExtractedEntry = result
            .entries
            .iter()
            .find(|e: &&ExtractedEntry| e.name == *name)
            .unwrap_or_else(|| {
                panic!(
                    "missing extracted file {name}; got {:?}",
                    result
                        .entries
                        .iter()
                        .map(|e: &ExtractedEntry| e.name.clone())
                        .collect::<Vec<String>>()
                )
            });
        let disk: &PathBuf = entry.disk_path.as_ref().expect("entry disk path");
        let recovered: Vec<u8> = std::fs::read(disk).expect("read extracted msi file");
        assert_eq!(
            &recovered,
            body,
            "byte-exact mismatch for msi file {name} (got {} want {})",
            recovered.len(),
            body.len()
        );
    }
}
