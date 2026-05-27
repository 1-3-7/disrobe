#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::io::{Cursor, Write};

use cfb::CompoundFile;
use disrobe_pass_shell::{
    ContainerKind, Detection, Dialect, ExtractedProject, PCodeDisasm, PCodeOpcode, VbsReport,
    deobfuscate_vbs, detect, disassemble_pcode, extract_from_bytes,
};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

fn build_minimal_ole() -> Vec<u8> {
    let buf: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut comp: CompoundFile<Cursor<Vec<u8>>> = CompoundFile::create(buf).expect("create cfb");
    comp.create_storage("/VBA").expect("create /VBA storage");
    let mut s: cfb::Stream<Cursor<Vec<u8>>> = comp
        .create_stream("/VBA/Module1")
        .expect("create /VBA/Module1 stream");
    s.write_all(
        b"Attribute VB_Name = \"Module1\"\nSub Auto_Open()\n  MsgBox \"hello vba\"\nEnd Sub\n",
    )
    .expect("write module bytes");
    drop(s);
    comp.flush().expect("flush cfb");
    let cur: Cursor<Vec<u8>> = comp.into_inner();
    cur.into_inner()
}

fn build_minimal_docm() -> Vec<u8> {
    let ole: Vec<u8> = build_minimal_ole();
    let out: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut zip: ZipWriter<Cursor<Vec<u8>>> = ZipWriter::new(out);
    let opts: SimpleFileOptions =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("[Content_Types].xml", opts).expect("ct");
    zip.write_all(b"<Types/>\n").expect("write ct");
    zip.start_file("word/vbaProject.bin", opts)
        .expect("vba entry");
    zip.write_all(&ole).expect("write ole bytes into zip");
    let inner: Cursor<Vec<u8>> = zip.finish().expect("finish zip");
    inner.into_inner()
}

#[test]
fn fixture_detects_ooxml_container() {
    let docm: Vec<u8> = build_minimal_docm();
    let det: Detection = detect(&docm);
    assert_eq!(det.dialect, Dialect::Vba);
}

#[test]
fn fixture_extracts_module_from_docm() -> disrobe_pass_shell::Result<()> {
    let docm: Vec<u8> = build_minimal_docm();
    let project: ExtractedProject = extract_from_bytes(&docm)?;
    assert_eq!(project.container_kind, ContainerKind::OoxmlZip);
    assert!(!project.modules.is_empty());
    let mod0: &disrobe_pass_shell::ExtractedModule = &project.modules[0];
    assert!(mod0.recovered_source.contains("hello vba"));
    Ok(())
}

#[test]
fn fixture_extracts_module_from_raw_ole() -> disrobe_pass_shell::Result<()> {
    let ole: Vec<u8> = build_minimal_ole();
    let project: ExtractedProject = extract_from_bytes(&ole)?;
    assert_eq!(project.container_kind, ContainerKind::OleCompoundFile);
    assert!(!project.modules.is_empty());
    assert!(
        project
            .modules
            .iter()
            .any(|m: &disrobe_pass_shell::ExtractedModule| m
                .recovered_source
                .contains("hello vba"))
    );
    Ok(())
}

#[test]
fn fixture_vbs_deobf_chr_chain() {
    let src: &str =
        r#"Execute(Chr(77) & Chr(115) & Chr(103) & Chr(66) & Chr(111) & Chr(120) & " ""hi""")"#;
    let r: VbsReport = deobfuscate_vbs(src);
    assert!(r.chr_substitutions >= 6);
    assert!(r.output.contains("MsgBox"));
}

#[test]
fn fixture_pcode_disasm_decodes_strings() -> disrobe_pass_shell::Result<()> {
    let mut stream: Vec<u8> = Vec::new();
    stream.extend_from_slice(&[0x03, 0x00]);
    stream.extend_from_slice(&(5u16).to_le_bytes());
    stream.extend_from_slice(b"calc!");
    stream.extend_from_slice(&[0x20, 0x00]);
    stream.extend_from_slice(&[0x30, 0x00]);
    let d: PCodeDisasm = disassemble_pcode(&stream)?;
    assert!(d.strings.contains(&"calc!".to_owned()));
    assert!(
        d.instructions
            .iter()
            .any(|i: &disrobe_pass_shell::PCodeInstruction| i.opcode == PCodeOpcode::Call)
    );
    Ok(())
}
