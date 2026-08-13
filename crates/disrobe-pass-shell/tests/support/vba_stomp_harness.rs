use std::io::{Cursor, Read as _, Seek as _, SeekFrom, Write as _};

use disrobe_pass_shell::{ExtractedModule, ExtractedProject, extract_from_bytes};

const OVBA_SIGNATURE_BYTE: u8 = 0x01;
const OVBA_CHUNK_SIGNATURE: u16 = 0x3000;
const OVBA_COMPRESSED_FLAG: u16 = 0x8000;
const OVBA_MAX_CHUNK_BODY: usize = 4096;
const OVBA_LITERALS_PER_TOKEN_GROUP: usize = 8;
const OVBA_MAX_LITERALS_PER_CHUNK: usize = 3640;

pub(crate) fn ovba_compress(plain: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![OVBA_SIGNATURE_BYTE];
    for chunk in plain.chunks(OVBA_MAX_LITERALS_PER_CHUNK) {
        let mut body: Vec<u8> = Vec::with_capacity(OVBA_MAX_CHUNK_BODY);
        for group in chunk.chunks(OVBA_LITERALS_PER_TOKEN_GROUP) {
            body.push(0x00);
            body.extend_from_slice(group);
        }
        assert!(
            !body.is_empty() && body.len() <= OVBA_MAX_CHUNK_BODY,
            "chunk body {} outside the MS-OVBA 1..=4096 range",
            body.len()
        );
        let encoded_size: u16 = u16::try_from(body.len() - 1).expect("chunk body fits 12 bits");
        let header: u16 = OVBA_COMPRESSED_FLAG | OVBA_CHUNK_SIGNATURE | encoded_size;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(&body);
    }
    out
}

pub(crate) fn module_stream_path(module: &str) -> String {
    format!("/VBA/{module}")
}

pub(crate) fn module_text_offset(container: &[u8], module: &str) -> usize {
    let project: ExtractedProject =
        extract_from_bytes(container).expect("extract the clean project");
    project
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.name.eq_ignore_ascii_case(module))
        .and_then(|m: &ExtractedModule| m.text_offset)
        .unwrap_or_else(|| panic!("module {module} carries no TextOffset"))
}

fn read_ole_stream(ole: &[u8], path: &str) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(ole.to_vec());
    let mut comp: cfb::CompoundFile<Cursor<Vec<u8>>> =
        cfb::CompoundFile::open(cursor).expect("open compound file");
    let mut handle: cfb::Stream<Cursor<Vec<u8>>> =
        comp.open_stream(path).expect("open compound file stream");
    let mut out: Vec<u8> = Vec::new();
    handle.read_to_end(&mut out).expect("read stream");
    out
}

fn write_ole_stream(ole: &[u8], path: &str, contents: &[u8]) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(ole.to_vec());
    let mut comp: cfb::CompoundFile<Cursor<Vec<u8>>> =
        cfb::CompoundFile::open(cursor).expect("open compound file");
    let mut handle: cfb::Stream<Cursor<Vec<u8>>> =
        comp.open_stream(path).expect("open compound file stream");
    handle.seek(SeekFrom::Start(0)).expect("rewind stream");
    handle.write_all(contents).expect("write stream");
    handle
        .set_len(contents.len() as u64)
        .expect("resize stream");
    handle.flush().expect("flush stream");
    drop(handle);
    comp.into_inner().into_inner()
}

fn replace_source_payload(ole: &[u8], module: &str, text_offset: usize, payload: &[u8]) -> Vec<u8> {
    let path: String = module_stream_path(module);
    let original: Vec<u8> = read_ole_stream(ole, &path);
    assert!(
        text_offset <= original.len(),
        "TextOffset {text_offset} beyond the {} byte module stream",
        original.len()
    );
    let mut rewritten: Vec<u8> = Vec::with_capacity(text_offset + payload.len());
    rewritten.extend_from_slice(&original[..text_offset]);
    rewritten.extend_from_slice(payload);
    write_ole_stream(ole, &path, &rewritten)
}

pub(crate) fn stomp_with_decoy_source(
    ole: &[u8],
    module: &str,
    text_offset: usize,
    decoy: &str,
) -> Vec<u8> {
    replace_source_payload(ole, module, text_offset, &ovba_compress(decoy.as_bytes()))
}

pub(crate) fn stomp_to_empty_source(ole: &[u8], module: &str, text_offset: usize) -> Vec<u8> {
    replace_source_payload(ole, module, text_offset, &[OVBA_SIGNATURE_BYTE])
}

pub(crate) fn stomp_with_junk_source(ole: &[u8], module: &str, text_offset: usize) -> Vec<u8> {
    replace_source_payload(ole, module, text_offset, b"STOMPED!")
}

pub(crate) fn stomp_by_truncating_at_source(
    ole: &[u8],
    module: &str,
    text_offset: usize,
) -> Vec<u8> {
    replace_source_payload(ole, module, text_offset, &[])
}

const REC_PROJECTMODULES: u16 = 0x000F;
const REC_MODULENAME: u16 = 0x0019;
const REC_MODULESTREAMNAME: u16 = 0x001A;
const REC_MODULEOFFSET: u16 = 0x0031;

fn push_dir_record(buf: &mut Vec<u8>, tag: u16, body: &[u8]) {
    buf.extend_from_slice(&tag.to_le_bytes());
    let size: u32 = u32::try_from(body.len()).expect("record body fits u32");
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(body);
}

pub(crate) fn dir_stream_declaring(module_count: usize) -> Vec<u8> {
    let declared: u16 = u16::try_from(module_count).unwrap_or(u16::MAX);
    let mut dir: Vec<u8> = Vec::new();
    push_dir_record(&mut dir, REC_PROJECTMODULES, &declared.to_le_bytes());
    for index in 0..module_count {
        let name: String = format!("Mod{index}");
        push_dir_record(&mut dir, REC_MODULENAME, name.as_bytes());
        push_dir_record(&mut dir, REC_MODULESTREAMNAME, name.as_bytes());
        push_dir_record(&mut dir, REC_MODULEOFFSET, &0_u32.to_le_bytes());
    }
    dir
}

pub(crate) fn replace_dir_stream(ole: &[u8], dir: &[u8]) -> Vec<u8> {
    write_ole_stream(ole, "/VBA/dir", &ovba_compress(dir))
}

pub(crate) fn repack_ooxml_with_vba_project(container: &[u8], vba_project: &[u8]) -> Vec<u8> {
    let read_cursor: Cursor<Vec<u8>> = Cursor::new(container.to_vec());
    let mut archive: zip::ZipArchive<Cursor<Vec<u8>>> =
        zip::ZipArchive::new(read_cursor).expect("open ooxml container");
    let write_cursor: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
    let mut writer: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(write_cursor);
    let mut replaced: bool = false;
    for index in 0..archive.len() {
        let mut entry: zip::read::ZipFile<'_> = archive.by_index(index).expect("zip entry");
        let name: String = entry.name().to_owned();
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        if entry.is_dir() {
            writer.add_directory(name, options).expect("add directory");
            continue;
        }
        let mut body: Vec<u8> = Vec::new();
        entry.read_to_end(&mut body).expect("read zip entry");
        drop(entry);
        writer.start_file(&name, options).expect("start zip entry");
        if name.to_ascii_lowercase().ends_with("vbaproject.bin") {
            writer.write_all(vba_project).expect("write vbaProject.bin");
            replaced = true;
        } else {
            writer.write_all(&body).expect("write zip entry");
        }
    }
    assert!(replaced, "container carries no vbaProject.bin to replace");
    writer
        .finish()
        .expect("finish ooxml container")
        .into_inner()
}

pub(crate) fn vba_project_of(container: &[u8]) -> Vec<u8> {
    disrobe_pass_shell::vba_project_bin_from_bytes(container).expect("locate vbaProject.bin")
}
