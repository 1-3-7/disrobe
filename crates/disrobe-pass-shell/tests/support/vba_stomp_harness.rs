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

pub(crate) fn module_stream_path(ole: &[u8], module: &str) -> String {
    let target: String = module.to_ascii_lowercase();
    stream_paths(ole)
        .into_iter()
        .find(|path: &String| {
            path.rsplit('/')
                .next()
                .is_some_and(|leaf: &str| leaf.eq_ignore_ascii_case(&target))
        })
        .unwrap_or_else(|| panic!("module stream for {module} is absent from the container"))
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
    let path: String = module_stream_path(ole, module);
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

pub(crate) fn patch_module_stream(ole: &[u8], module: &str, at: usize, bytes: &[u8]) -> Vec<u8> {
    let path: String = module_stream_path(ole, module);
    let mut stream: Vec<u8> = read_ole_stream(ole, &path);
    let end: usize = at + bytes.len();
    assert!(
        end <= stream.len(),
        "patch of {} bytes at {at} runs past the {} byte module stream",
        bytes.len(),
        stream.len()
    );
    stream[at..end].copy_from_slice(bytes);
    write_ole_stream(ole, &path, &stream)
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
    let path: String = module_stream_path(ole, "dir");
    write_ole_stream(ole, &path, &ovba_compress(dir))
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

fn stream_paths(ole: &[u8]) -> Vec<String> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(ole.to_vec());
    let comp: cfb::CompoundFile<Cursor<Vec<u8>>> =
        cfb::CompoundFile::open(cursor).expect("open compound file");
    comp.walk()
        .filter(|e: &cfb::Entry| e.is_stream())
        .map(|e: cfb::Entry| e.path().display().to_string().replace('\\', "/"))
        .collect()
}

fn rehost_under(ole: &[u8], project_storages: &[&str], extra_root: &[(&str, &[u8])]) -> Vec<u8> {
    let out_cursor: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
    let mut out: cfb::CompoundFile<Cursor<Vec<u8>>> =
        cfb::CompoundFile::create(out_cursor).expect("create compound file");
    for (name, body) in extra_root {
        let mut handle: cfb::Stream<Cursor<Vec<u8>>> = out
            .create_new_stream(format!("/{name}"))
            .expect("create root stream");
        handle.write_all(body).expect("write root stream");
        handle.flush().expect("flush root stream");
    }
    let paths: Vec<String> = stream_paths(ole);
    for project_storage in project_storages {
        out.create_storage_all(format!("/{project_storage}"))
            .expect("create project storage");
        for path in &paths {
            let body: Vec<u8> = read_ole_stream(ole, path);
            let target: String = format!("/{project_storage}{path}");
            let parent: &str = target.rsplit_once('/').map_or("/", |(head, _)| head);
            if !parent.is_empty() {
                out.create_storage_all(parent)
                    .expect("create parent storage");
            }
            let mut handle: cfb::Stream<Cursor<Vec<u8>>> =
                out.create_new_stream(&target).expect("create stream");
            handle.write_all(&body).expect("write stream");
            handle.flush().expect("flush stream");
        }
    }
    out.flush().expect("flush compound file");
    out.into_inner().into_inner()
}

pub(crate) fn legacy_doc_container(vba_project: &[u8]) -> Vec<u8> {
    rehost_under(
        vba_project,
        &["Macros"],
        &[("WordDocument", &[0xEC, 0xA5, 0xC1, 0x00])],
    )
}

pub(crate) fn legacy_xls_container(vba_project: &[u8]) -> Vec<u8> {
    rehost_under(
        vba_project,
        &["_VBA_PROJECT_CUR"],
        &[("Workbook", &[0x09, 0x08, 0x10, 0x00])],
    )
}

pub(crate) const SECOND_PROJECT_STORAGE: &str = "/_VBA_PROJECT_CUR/VBA";

pub(crate) fn two_project_container(vba_project: &[u8]) -> Vec<u8> {
    rehost_under(
        vba_project,
        &["Macros", "_VBA_PROJECT_CUR"],
        &[("WordDocument", &[0xEC, 0xA5, 0xC1, 0x00])],
    )
}

const PPTM_CONTENT_TYPES: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">"#,
    r#"<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>"#,
    r#"<Default Extension="xml" ContentType="application/xml"/>"#,
    r#"<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>"#,
    r#"<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"/>"#,
    r#"</Types>"#
);

const PPTM_ROOT_RELS: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    r#"<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>"#,
    r#"</Relationships>"#
);

const PPTM_PRESENTATION_RELS: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    r#"<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>"#,
    r#"</Relationships>"#
);

const PPTM_PRESENTATION: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" "#,
    r#"xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" "#,
    r#"xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">"#,
    r#"<p:sldMasterIdLst/><p:sldIdLst/><p:sldSz cx="9144000" cy="6858000"/>"#,
    r#"<p:notesSz cx="6858000" cy="9144000"/></p:presentation>"#
);

pub(crate) fn pptm_container(vba_project: &[u8]) -> Vec<u8> {
    let write_cursor: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
    let mut writer: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(write_cursor);
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in [
        ("[Content_Types].xml", PPTM_CONTENT_TYPES.as_bytes()),
        ("_rels/.rels", PPTM_ROOT_RELS.as_bytes()),
        ("ppt/presentation.xml", PPTM_PRESENTATION.as_bytes()),
        (
            "ppt/_rels/presentation.xml.rels",
            PPTM_PRESENTATION_RELS.as_bytes(),
        ),
        ("ppt/vbaProject.bin", vba_project),
    ] {
        writer.start_file(name, options).expect("start zip entry");
        writer.write_all(body).expect("write zip entry");
    }
    writer.finish().expect("finish pptm container").into_inner()
}
