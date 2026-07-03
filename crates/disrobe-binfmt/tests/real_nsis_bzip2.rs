#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_binfmt::containers::nsis::{
    NsisArchive, NsisCompression, decode_solid_region, decompress_file, parse_nsis_archive,
    slice_solid_file,
};

fn find_makensis() -> Option<PathBuf> {
    if let Ok(found) = which("makensis") {
        return Some(found);
    }
    if cfg!(windows) {
        let candidates: [&str; 2] = [
            r"C:\Program Files (x86)\NSIS\makensis.exe",
            r"C:\Program Files\NSIS\makensis.exe",
        ];
        return candidates
            .iter()
            .map(PathBuf::from)
            .find(|p: &PathBuf| p.exists());
    }
    None
}

fn which(tool: &str) -> Result<PathBuf, ()> {
    let path: String = std::env::var("PATH").map_err(|_| ())?;
    for dir in std::env::split_paths(&path) {
        for ext in ["", ".exe"] {
            let candidate: PathBuf = dir.join(format!("{tool}{ext}"));
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(())
}

fn build_installer(
    makensis: &Path,
    dir: &Path,
    solid: bool,
    payloads: &[(&str, &[u8])],
) -> Vec<u8> {
    std::fs::create_dir_all(dir).expect("mk dir");
    let mut script: String = String::new();
    if solid {
        script.push_str("SetCompressor /SOLID /FINAL bzip2\n");
    } else {
        script.push_str("SetCompressor /FINAL bzip2\n");
    }
    script.push_str("Name \"drbz2\"\n");
    let out_name: &str = if solid { "solid.exe" } else { "plain.exe" };
    push_line(&mut script, &format!("OutFile \"{out_name}\""));
    script.push_str("InstallDir \"$TEMP\\drbz2\"\nSection\n  SetOutPath \"$INSTDIR\"\n");
    for (name, body) in payloads {
        std::fs::write(dir.join(name), body).expect("write payload");
        push_line(&mut script, &format!("  File \"{name}\""));
    }
    script.push_str("SectionEnd\n");
    let nsi: PathBuf = dir.join(if solid { "solid.nsi" } else { "plain.nsi" });
    std::fs::write(&nsi, script).expect("write nsi");
    let status = Command::new(makensis)
        .arg("/V2")
        .arg(&nsi)
        .current_dir(dir)
        .status()
        .expect("run makensis");
    assert!(status.success(), "makensis failed");
    std::fs::read(dir.join(out_name)).expect("read installer")
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn make_payloads() -> Vec<(&'static str, Vec<u8>)> {
    let mut p1: Vec<u8> = Vec::new();
    for _ in 0..40 {
        p1.extend_from_slice(b"The quick brown fox jumps over the lazy dog. ");
    }
    p1.extend((0u16..512).map(|n: u16| (n & 0xff) as u8));
    let mut p2: Vec<u8> = Vec::new();
    for i in 0..1500u32 {
        p2.push((i.wrapping_mul(31).wrapping_add(7) & 0xff) as u8);
    }
    vec![("payload1.bin", p1), ("payload2.bin", p2)]
}

#[test]
fn makensis_bzip2_non_solid_round_trips() {
    let Some(makensis): Option<PathBuf> = find_makensis() else {
        eprintln!("skipping: makensis not installed");
        return;
    };
    let dir: PathBuf = std::env::temp_dir().join("disrobe_nsis_bz2_nonsolid");
    let payloads: Vec<(&str, Vec<u8>)> = make_payloads();
    let refs: Vec<(&str, &[u8])> = payloads
        .iter()
        .map(|(n, b): &(&str, Vec<u8>)| (*n, b.as_slice()))
        .collect();
    let exe: Vec<u8> = build_installer(&makensis, &dir, false, &refs);

    let archive: NsisArchive = parse_nsis_archive(&exe).expect("parse non-solid archive");
    assert_eq!(archive.compression, NsisCompression::Bzip2);
    for (name, body) in &payloads {
        let entry = archive
            .files
            .iter()
            .find(|f| f.name.ends_with(name))
            .unwrap_or_else(|| panic!("missing entry {name}"));
        let recovered: Vec<u8> =
            decompress_file(&exe, &archive, entry, u64::MAX).expect("decompress file");
        assert_eq!(&recovered, body, "byte-exact mismatch for {name}");
    }
}

#[test]
fn makensis_bzip2_solid_round_trips() {
    let Some(makensis): Option<PathBuf> = find_makensis() else {
        eprintln!("skipping: makensis not installed");
        return;
    };
    let dir: PathBuf = std::env::temp_dir().join("disrobe_nsis_bz2_solid");
    let payloads: Vec<(&str, Vec<u8>)> = make_payloads();
    let refs: Vec<(&str, &[u8])> = payloads
        .iter()
        .map(|(n, b): &(&str, Vec<u8>)| (*n, b.as_slice()))
        .collect();
    let exe: Vec<u8> = build_installer(&makensis, &dir, true, &refs);

    let archive: NsisArchive = parse_nsis_archive(&exe).expect("parse solid archive");
    assert_eq!(archive.compression, NsisCompression::Bzip2);
    assert!(archive.solid, "expected solid archive");
    let solid: Vec<u8> =
        decode_solid_region(&exe, &archive, u64::MAX).expect("decode solid region");
    for (name, body) in &payloads {
        let entry = archive
            .files
            .iter()
            .find(|f| f.name.ends_with(name))
            .unwrap_or_else(|| panic!("missing entry {name}"));
        let recovered: Vec<u8> = slice_solid_file(&solid, entry, u64::MAX).expect("slice solid");
        assert_eq!(&recovered, body, "byte-exact mismatch for {name}");
    }
}
