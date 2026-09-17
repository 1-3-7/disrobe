#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use disrobe_pass_native::{
    OverlayArchiveKind, OverlayClass, OverlaySegment, PeOverlayReport, analyze_pe_overlay,
    carve_pe_overlay,
};

fn corpus(rel: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push(rel);
    fs::read(&p).unwrap_or_else(|_| panic!("committed corpus sample missing: corpus/{rel}"))
}

fn real_payload() -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    for i in 0..512u32 {
        payload
            .extend_from_slice(format!("disrobe overlay extent oracle line {i:04}\n").as_bytes());
    }
    payload
}

fn gzip_archive(payload: &[u8]) -> Vec<u8> {
    let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn multi_member_gzip(payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = gzip_archive(&payload[..payload.len() / 2]);
    out.extend_from_slice(&gzip_archive(&payload[payload.len() / 2..]));
    out
}

fn xz_archive(payload: &[u8]) -> Vec<u8> {
    use std::io::Read as _;
    let mut out: Vec<u8> = Vec::new();
    let mut encoder: liblzma::read::XzEncoder<&[u8]> = liblzma::read::XzEncoder::new(payload, 6);
    encoder.read_to_end(&mut out).expect("xz encode");
    out
}

fn zstd_archive(payload: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(Cursor::new(payload), 3).expect("zstd encode")
}

fn tar_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder: tar::Builder<Vec<u8>> = tar::Builder::new(Vec::new());
    for (name, data) in entries {
        let mut header: tar::Header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, Cursor::new(*data))
            .expect("tar append");
    }
    builder.into_inner().expect("tar finish")
}

fn sevenz_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut writer: sevenz_rust2::SevenZWriter<Cursor<Vec<u8>>> =
        sevenz_rust2::SevenZWriter::new(cursor).expect("7z writer");
    for (name, data) in entries {
        let entry: sevenz_rust2::SevenZArchiveEntry =
            sevenz_rust2::SevenZArchiveEntry::new_file(name);
        writer
            .push_archive_entry(entry, Some(Cursor::new(data.to_vec())))
            .expect("7z push");
    }
    writer.finish().expect("7z finish").into_inner()
}

fn cab_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder: cab::CabinetBuilder = cab::CabinetBuilder::new();
    {
        let folder: &mut cab::FolderBuilder = builder.add_folder(cab::CompressionType::None);
        for (name, _) in entries {
            folder.add_file(*name);
        }
    }
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut writer: cab::CabinetWriter<Cursor<Vec<u8>>> = builder.build(cursor).expect("cab build");
    let mut idx: usize = 0;
    while let Some(mut fw) = writer.next_file().expect("cab next") {
        fw.write_all(entries[idx].1).expect("cab write");
        idx += 1;
    }
    writer.finish().expect("cab finish").into_inner()
}

const RAR5_MAGIC: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
const RAR4_MAGIC: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
const RAR5_HEADER_FLAG_DATA: u64 = 0x0002;
const RAR5_HEAD_ENDARC: u64 = 5;
const RAR4_FLAG_DATA: u16 = 0x8000;
const RAR4_TYPE_ENDARC: u8 = 0x7b;
const RAR4_BLOCK_HEADER: usize = 7;

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher: crc32fast::Hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn rar5_vint_write(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte: u8 = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn rar5_block(header_type: u64, header_flags: u64, data: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    rar5_vint_write(&mut body, header_type);
    rar5_vint_write(&mut body, header_flags);
    if header_flags & RAR5_HEADER_FLAG_DATA != 0 {
        rar5_vint_write(&mut body, data.len() as u64);
    }
    let mut block: Vec<u8> = Vec::new();
    block.extend_from_slice(&crc32(&body).to_le_bytes());
    rar5_vint_write(&mut block, body.len() as u64);
    block.extend_from_slice(&body);
    block.extend_from_slice(data);
    block
}

fn rar5_archive(file_body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = RAR5_MAGIC.to_vec();
    out.extend_from_slice(&rar5_block(1, 0, &[]));
    out.extend_from_slice(&rar5_block(2, RAR5_HEADER_FLAG_DATA, file_body));
    out.extend_from_slice(&rar5_block(RAR5_HEAD_ENDARC, 0, &[]));
    out
}

fn rar4_block(head_type: u8, head_flags: u16, data: &[u8]) -> Vec<u8> {
    let has_data: bool = head_flags & RAR4_FLAG_DATA != 0;
    let head_size: u16 = if has_data {
        (RAR4_BLOCK_HEADER + 4) as u16
    } else {
        RAR4_BLOCK_HEADER as u16
    };
    let mut block: Vec<u8> = Vec::new();
    block.extend_from_slice(&[0x00, 0x00]);
    block.push(head_type);
    block.extend_from_slice(&head_flags.to_le_bytes());
    block.extend_from_slice(&head_size.to_le_bytes());
    if has_data {
        block.extend_from_slice(&(data.len() as u32).to_le_bytes());
        block.extend_from_slice(data);
    }
    block
}

fn rar4_archive(file_body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = RAR4_MAGIC.to_vec();
    out.extend_from_slice(&rar4_block(0x73, 0x0000, &[]));
    out.extend_from_slice(&rar4_block(0x74, RAR4_FLAG_DATA, file_body));
    out.extend_from_slice(&rar4_block(RAR4_TYPE_ENDARC, 0x0000, &[]));
    out
}

struct OverlayCase {
    archive_bytes: Vec<u8>,
    expected_kind: OverlayArchiveKind,
}

fn assert_overlay_extent(case: OverlayCase) {
    let original: Vec<u8> = corpus("native/packers/upx/hello.original.exe");
    let clean: PeOverlayReport = analyze_pe_overlay(&original).expect("analyze base");
    assert_eq!(
        clean.overlay_len, 0,
        "base PE fixture must itself be overlay-free"
    );
    let real_image_end: u64 = clean.image_end;
    assert_eq!(real_image_end, original.len() as u64);

    let archive_len: usize = case.archive_bytes.len();
    let padding_byte: u8 = 0xAA;
    let padding_len: usize = 3333;
    let padding: Vec<u8> = vec![padding_byte; padding_len];

    let mut inflated: Vec<u8> = original;
    inflated.extend_from_slice(&case.archive_bytes);
    inflated.extend_from_slice(&padding);

    let report: PeOverlayReport = analyze_pe_overlay(&inflated).expect("analyze inflated");
    assert_eq!(report.image_end, real_image_end);
    assert_eq!(report.overlay_offset, real_image_end);
    assert_eq!(
        report.overlay_len,
        (archive_len + padding_len) as u64,
        "overlay covers the appended archive plus padding"
    );

    let carved: &[u8] = carve_pe_overlay(&inflated).expect("carve");
    assert_eq!(carved.len(), archive_len + padding_len);

    let archive_seg: &OverlaySegment = report
        .segments
        .iter()
        .find(|s: &&OverlaySegment| matches!(s.class, OverlayClass::AppendedArchive { .. }))
        .unwrap_or_else(|| {
            panic!(
                "no archive segment for {:?}: {:?}",
                case.expected_kind, report.segments
            )
        });

    let OverlayClass::AppendedArchive { archive, length } = archive_seg.class else {
        unreachable!()
    };
    assert_eq!(
        archive, case.expected_kind,
        "archive segment misclassified: {:?}",
        report.segments
    );
    assert_eq!(
        archive_seg.offset, real_image_end,
        "archive segment must begin exactly at the overlay start"
    );
    assert_eq!(
        length, archive_len as u64,
        "computed true-extent for {:?} must equal the real archive's exact byte length \
         (real={archive_len}); segments={:?}",
        case.expected_kind, report.segments
    );

    let padding_seg: &OverlaySegment = report
        .segments
        .iter()
        .find(|s: &&OverlaySegment| matches!(s.class, OverlayClass::ConstantPadding { .. }))
        .unwrap_or_else(|| {
            panic!(
                "trailing padding after {:?} was not split off: {:?}",
                case.expected_kind, report.segments
            )
        });
    assert_eq!(
        padding_seg.offset,
        real_image_end + archive_len as u64,
        "padding must begin exactly where the real archive ends"
    );
    let OverlayClass::ConstantPadding { fill_byte, length } = padding_seg.class else {
        unreachable!()
    };
    assert_eq!(fill_byte, padding_byte);
    assert_eq!(
        length, padding_len as u64,
        "the entire trailing padding must be one constant-padding segment"
    );
}

#[test]
fn gzip_overlay_extent_matches_real_archive() {
    let payload: Vec<u8> = real_payload();
    assert_overlay_extent(OverlayCase {
        archive_bytes: gzip_archive(&payload),
        expected_kind: OverlayArchiveKind::Gzip,
    });
}

#[test]
fn multi_member_gzip_overlay_extent_matches_real_archive() {
    let payload: Vec<u8> = real_payload();
    let archive: Vec<u8> = multi_member_gzip(&payload);
    assert_overlay_extent(OverlayCase {
        archive_bytes: archive,
        expected_kind: OverlayArchiveKind::Gzip,
    });
}

#[test]
fn xz_overlay_extent_matches_real_archive() {
    let payload: Vec<u8> = real_payload();
    assert_overlay_extent(OverlayCase {
        archive_bytes: xz_archive(&payload),
        expected_kind: OverlayArchiveKind::Xz,
    });
}

#[test]
fn zstd_overlay_extent_matches_real_archive() {
    let payload: Vec<u8> = real_payload();
    assert_overlay_extent(OverlayCase {
        archive_bytes: zstd_archive(&payload),
        expected_kind: OverlayArchiveKind::Zstd,
    });
}

#[test]
fn bzip2_overlay_extent_matches_real_archive() {
    let archive: Vec<u8> = corpus("native/overlay/overlay.rs.bz2");
    assert!(
        archive.starts_with(b"BZh"),
        "fixture must be a real bzip2 stream"
    );
    assert_overlay_extent(OverlayCase {
        archive_bytes: archive,
        expected_kind: OverlayArchiveKind::Bzip2,
    });
}

#[test]
fn tar_overlay_extent_matches_real_archive() {
    let payload: Vec<u8> = real_payload();
    let archive: Vec<u8> = tar_archive(&[
        ("data/first.txt", &payload[..payload.len() / 2]),
        ("data/second.txt", &payload[payload.len() / 2..]),
    ]);
    assert_overlay_extent(OverlayCase {
        archive_bytes: archive,
        expected_kind: OverlayArchiveKind::Tar,
    });
}

#[test]
fn sevenz_overlay_extent_matches_real_archive() {
    let payload: Vec<u8> = real_payload();
    let archive: Vec<u8> = sevenz_archive(&[("payload.txt", &payload)]);
    assert!(
        archive.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
        "fixture must be a real 7z stream"
    );
    assert_overlay_extent(OverlayCase {
        archive_bytes: archive,
        expected_kind: OverlayArchiveKind::SevenZ,
    });
}

#[test]
fn cab_overlay_extent_matches_real_archive() {
    let payload: Vec<u8> = real_payload();
    let archive: Vec<u8> = cab_archive(&[("readme.txt", &payload)]);
    assert!(
        archive.starts_with(b"MSCF"),
        "fixture must be a real cab stream"
    );
    assert_overlay_extent(OverlayCase {
        archive_bytes: archive,
        expected_kind: OverlayArchiveKind::Cab,
    });
}

#[test]
fn rar5_overlay_extent_matches_spec_archive() {
    let payload: Vec<u8> = real_payload();
    let archive: Vec<u8> = rar5_archive(&payload);
    assert!(
        archive.starts_with(b"Rar!\x1a\x07\x01\x00"),
        "fixture must carry the RAR5 signature"
    );
    assert_overlay_extent(OverlayCase {
        archive_bytes: archive,
        expected_kind: OverlayArchiveKind::Rar,
    });
}

#[test]
fn rar4_overlay_extent_matches_spec_archive() {
    let payload: Vec<u8> = real_payload();
    let archive: Vec<u8> = rar4_archive(&payload);
    assert!(
        archive.starts_with(b"Rar!\x1a\x07\x00"),
        "fixture must carry the RAR4 signature"
    );
    assert_overlay_extent(OverlayCase {
        archive_bytes: archive,
        expected_kind: OverlayArchiveKind::Rar,
    });
}
