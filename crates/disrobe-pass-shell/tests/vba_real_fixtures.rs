#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::io::Read;
use std::path::PathBuf;

use disrobe_pass_shell::{
    ContainerKind, Detection, Dialect, ExtractedProject, PCodeDisasm, PCodeStreamHeader, PCodeWall,
    detect, disassemble_pcode, extract_from_bytes,
};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn read_corpus(relative: &str) -> Vec<u8> {
    let p: PathBuf = corpus_path(relative);
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

#[test]
fn real_docm_detects_as_vba_dialect() {
    let data: Vec<u8> = read_corpus("vba/hello.docm");
    let det: Detection = detect(&data);
    assert_eq!(det.dialect, Dialect::Vba);
}

#[test]
fn real_docm_extracts_modules_via_ms_ovba_decompress() -> disrobe_pass_shell::Result<()> {
    let data: Vec<u8> = read_corpus("vba/hello.docm");
    let project: ExtractedProject = extract_from_bytes(&data)?;
    assert_eq!(project.container_kind, ContainerKind::OoxmlZip);
    assert!(
        !project.modules.is_empty(),
        "expected at least one extracted VBA module"
    );
    let any_hello: bool = project
        .modules
        .iter()
        .any(|m: &disrobe_pass_shell::ExtractedModule| m.recovered_source.contains("hello world"));
    assert!(
        any_hello,
        "expected MS-OVBA decompression to recover 'hello world' from real docm fixture; modules={:?}",
        project
            .modules
            .iter()
            .map(|m: &disrobe_pass_shell::ExtractedModule| &m.name)
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn real_vba_project_bin_extracts_modules() -> disrobe_pass_shell::Result<()> {
    let data: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let project: ExtractedProject = extract_from_bytes(&data)?;
    assert_eq!(project.container_kind, ContainerKind::OleCompoundFile);
    assert!(!project.modules.is_empty());
    Ok(())
}

#[test]
fn real_vba_project_pcode_entry_routes_to_real_decoder() -> disrobe_pass_shell::Result<()> {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let d: PCodeDisasm = disassemble_pcode(&raw)?;
    let header: &PCodeStreamHeader = d.header.as_ref().expect("header parsed");
    assert_eq!(header.magic, 0x61CC, "magic must match _VBA_PROJECT marker");
    assert!(
        !d.instructions.is_empty(),
        "full OLE input must route through the real p-code decoder"
    );
    assert!(
        d.strings.iter().any(|s: &String| s == "hello world"),
        "real p-code route must surface the fixture string literals; strings={:?}",
        d.strings
    );
    assert!(
        !d.walls
            .iter()
            .any(|w: &disrobe_pass_shell::PCodeWallDetail| {
                matches!(
                    w.kind,
                    PCodeWall::UnsupportedVersion | PCodeWall::InsufficientStreamBytes
                )
            }),
        "full OLE p-code route must not report the legacy cache-stream wall; walls={:?}",
        d.walls
    );
    Ok(())
}

#[test]
fn real_vba_project_pcode_parses_header_with_honest_wall() -> disrobe_pass_shell::Result<()> {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(&raw[..]);
    let mut comp: cfb::CompoundFile<std::io::Cursor<&[u8]>> =
        cfb::CompoundFile::open(cursor).expect("open ole compound file");
    let mut stream: cfb::Stream<std::io::Cursor<&[u8]>> = comp
        .open_stream("/VBA/_VBA_PROJECT")
        .expect("open _VBA_PROJECT");
    let mut buf: Vec<u8> = Vec::new();
    stream.read_to_end(&mut buf).expect("read _VBA_PROJECT");
    let d: PCodeDisasm = disassemble_pcode(&buf)?;
    let header: &PCodeStreamHeader = d.header.as_ref().expect("header parsed");
    assert_eq!(header.magic, 0x61CC, "magic must match _VBA_PROJECT marker");
    assert!(
        header.version > 0,
        "version must be non-zero from real fixture"
    );
    assert!(
        d.walls
            .iter()
            .any(|w: &disrobe_pass_shell::PCodeWallDetail| w.kind
                == PCodeWall::InsufficientStreamBytes),
        "bare _VBA_PROJECT cache-stream input must surface the missing dir/module stream wall; walls={:?}",
        d.walls
    );
    assert!(
        d.instructions.is_empty(),
        "honest detect-only must NOT fabricate any instructions"
    );
    Ok(())
}

#[test]
fn pcode_disasm_emits_no_fabricated_strings_or_instructions() -> disrobe_pass_shell::Result<()> {
    let raw: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(&raw[..]);
    let mut comp: cfb::CompoundFile<std::io::Cursor<&[u8]>> =
        cfb::CompoundFile::open(cursor).expect("open ole compound file");
    let mut stream: cfb::Stream<std::io::Cursor<&[u8]>> = comp
        .open_stream("/VBA/_VBA_PROJECT")
        .expect("open _VBA_PROJECT");
    let mut buf: Vec<u8> = Vec::new();
    stream.read_to_end(&mut buf).expect("read _VBA_PROJECT");
    let d: PCodeDisasm = disassemble_pcode(&buf)?;
    assert!(d.strings.is_empty());
    assert!(d.instructions.is_empty());
    Ok(())
}
