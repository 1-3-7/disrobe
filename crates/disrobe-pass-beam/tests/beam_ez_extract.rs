#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use std::io::Write;

use disrobe_pass_beam::{BeamFile, EzArchive};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, build_expt, encode_compact_small,
};

fn build_inner_beam() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["inside", "ping"]);
    let mut code: Vec<u8> = Vec::new();
    code.push(1u8);
    code.extend(encode_compact_small(0, 1));
    code.push(2u8);
    code.extend(encode_compact_small(2, 1));
    code.extend(encode_compact_small(2, 2));
    code.extend(encode_compact_small(0, 0));
    code.push(1u8);
    code.extend(encode_compact_small(0, 2));
    code.push(19u8);
    code.push(3u8);
    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(2, 1, &code)),
        build_chunk(b"ExpT", &build_expt(&[(2u32, 0u32, 2u32)])),
    ];
    build_beam(&chunks)
}

fn build_ez_archive() -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut writer: ZipWriter<std::io::Cursor<&mut Vec<u8>>> =
            ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        writer
            .start_file("my_app-1.0.0/ebin/inside.beam", opts)
            .expect("start file");
        writer.write_all(&build_inner_beam()).expect("write beam");
        writer
            .start_file("my_app-1.0.0/ebin/my_app.app", opts)
            .expect("start app");
        writer
            .write_all(b"{application,my_app,[{vsn,\"1.0.0\"}]}.")
            .expect("write app");
        writer.finish().expect("finish");
    }
    buf
}

#[test]
fn ez_archive_lists_files() {
    let buf: Vec<u8> = build_ez_archive();
    let archive: EzArchive = EzArchive::parse(&buf).expect("parse ez");
    assert!(
        archive
            .entries
            .contains_key("my_app-1.0.0/ebin/inside.beam")
    );
    assert!(archive.entries.contains_key("my_app-1.0.0/ebin/my_app.app"));
}

#[test]
fn ez_beam_round_trips_to_parsed_module() {
    let buf: Vec<u8> = build_ez_archive();
    let archive: EzArchive = EzArchive::parse(&buf).expect("parse ez");
    let beams = archive.beam_files();
    assert_eq!(beams.len(), 1);
    let beam_entry = beams[0];
    let beam: BeamFile = BeamFile::parse(&beam_entry.data).expect("parse inner beam");
    assert_eq!(beam.module_name(), Some("inside"));
    assert_eq!(beam.chunks.exports.len(), 1);
}
