#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;

use disrobe_pass_jvm::{
    Error, Jimage, JmodExtract, extract_jmod, parse_jimage, parse_jimage_header,
};
use zip::write::SimpleFileOptions;

fn build_jmod(magic: [u8; 4]) -> Vec<u8> {
    let mut zip_buf: Vec<u8> = Vec::new();
    {
        let cursor: std::io::Cursor<&mut Vec<u8>> = std::io::Cursor::new(&mut zip_buf);
        let mut zw: zip::ZipWriter<std::io::Cursor<&mut Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zw.start_file("classes/module-info.class", opts)
            .expect("start");
        zw.write_all(&[0xCA, 0xFE, 0xBA, 0xBE]).expect("write");
        zw.start_file("classes/Foo.class", opts).expect("start");
        zw.write_all(&[0xCA, 0xFE, 0xBA, 0xBE]).expect("write");
        zw.start_file("lib/libx.so", opts).expect("start");
        zw.write_all(b"\x7fELF").expect("write");
        zw.start_file("conf/app.cfg", opts).expect("start");
        zw.write_all(b"k=v").expect("write");
        zw.finish().expect("finish");
    }
    let mut out: Vec<u8> = Vec::with_capacity(4 + zip_buf.len());
    out.extend_from_slice(&magic);
    out.extend_from_slice(&zip_buf);
    out
}

fn build_jimage_le() -> (Vec<u8>, String) {
    let mut strings: Vec<u8> = Vec::new();
    strings.push(0);
    let mod_off: u8 = strings.len() as u8;
    strings.extend_from_slice(b"jdk.base\0");
    let base_off: u8 = strings.len() as u8;
    strings.extend_from_slice(b"Foo\0");
    let ext_off: u8 = strings.len() as u8;
    strings.extend_from_slice(b"class\0");

    let mut loc: Vec<u8> = Vec::new();
    loc.push(0);
    let record_off: u32 = loc.len() as u32;
    let push_attr = |v: &mut Vec<u8>, kind: u8, val: u8| {
        let length_minus_one: u8 = 0;
        v.push((kind << 3) | length_minus_one);
        v.push(val);
    };
    push_attr(&mut loc, 1, mod_off);
    push_attr(&mut loc, 3, base_off);
    push_attr(&mut loc, 4, ext_off);
    loc.push(0);

    let table_length: u32 = 1;
    let locations_size: u32 = loc.len() as u32;
    let strings_size: u32 = strings.len() as u32;

    let mut img: Vec<u8> = Vec::new();
    img.extend_from_slice(&disrobe_pass_jvm::JIMAGE_MAGIC.to_le_bytes());
    img.extend_from_slice(&1u16.to_le_bytes());
    img.extend_from_slice(&0u16.to_le_bytes());
    img.extend_from_slice(&0u32.to_le_bytes());
    img.extend_from_slice(&1u32.to_le_bytes());
    img.extend_from_slice(&table_length.to_le_bytes());
    img.extend_from_slice(&locations_size.to_le_bytes());
    img.extend_from_slice(&strings_size.to_le_bytes());
    img.extend_from_slice(&(-1i32).to_le_bytes());
    img.extend_from_slice(&record_off.to_le_bytes());
    img.extend_from_slice(&loc);
    img.extend_from_slice(&strings);

    (img, "/jdk.base/Foo.class".to_owned())
}

#[test]
fn jmod_full_magic_and_sections() {
    let jx: JmodExtract = extract_jmod(&build_jmod([0x4A, 0x4D, 0x01, 0x00])).expect("valid jmod");
    assert_eq!(jx.classes.len(), 2);
    assert!(jx.classes.contains_key("classes/Foo.class"));
    assert!(jx.classes.contains_key("classes/module-info.class"));
    assert_eq!(jx.native_libs.len(), 1);
    assert!(jx.native_libs.contains_key("lib/libx.so"));
    assert_eq!(jx.config.len(), 1);
    assert!(jx.config.contains_key("conf/app.cfg"));
}

#[test]
fn jmod_rejects_wrong_version_bytes() {
    let err: Error = extract_jmod(&build_jmod([0x4A, 0x4D, 0xFF, 0xFF])).expect_err("bad version");
    assert!(matches!(err, Error::BadJmodMagic([0x4A, 0x4D, 0xFF, 0xFF])));
}

#[test]
fn jimage_full_parse_reconstructs_name() {
    let (img, expected): (Vec<u8>, String) = build_jimage_le();
    let parsed: Jimage = parse_jimage(&img).expect("valid jimage");
    assert_eq!(parsed.header.version_major, 1);
    assert!(!parsed.endian_big);
    assert_eq!(parsed.resources.len(), 1);
    let r: &disrobe_pass_jvm::JimageResource = &parsed.resources[0];
    assert_eq!(r.module, "jdk.base");
    assert_eq!(r.parent, "");
    assert_eq!(r.base, "Foo");
    assert_eq!(r.extension, "class");
    assert_eq!(r.full_name, expected);
}

#[test]
fn jimage_header_rejects_bad_magic() {
    let err: Error = parse_jimage_header(&[0u8; 32]).expect_err("bad magic");
    assert!(matches!(err, Error::BadJimageMagic(_)));
}

#[test]
fn jimage_rejects_truncated_header() {
    let err: Error = parse_jimage_header(&[0xDA, 0xDA, 0xFE, 0xCA, 0x00]).expect_err("short");
    assert!(matches!(err, Error::Truncated { needed: 28, .. }));
}

#[test]
fn jimage_rejects_offset_region_overrun() {
    let (mut img, _): (Vec<u8>, String) = build_jimage_le();
    img.truncate(30);
    let err: Error = parse_jimage(&img).expect_err("overrun");
    assert!(matches!(
        err,
        Error::JimageOutOfRange { .. } | Error::Truncated { .. }
    ));
}
