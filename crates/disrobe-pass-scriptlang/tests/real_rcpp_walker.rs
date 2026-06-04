#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_scriptlang::lang::r_rds::read_rds;
use disrobe_pass_scriptlang::lang::rcpp::{NativeImageFormat, RcppFingerprint, fingerprint};
use disrobe_pass_scriptlang::lang::{analyze_rcpp, classify};
use disrobe_pass_scriptlang::{RdsObject, ScriptLang};

const HELLO_RDS: &[u8] = include_bytes!("fixtures/hello.rds");

const NILVALUE_SXP: u32 = 254u32;
const SYMSXP: u32 = 1u32;
const LISTSXP: u32 = 2u32;
const CHARSXP: u32 = 9u32;
const STRSXP: u32 = 16u32;
const RAWSXP: u32 = 24u32;
const VECSXP: u32 = 19u32;
const HAS_ATTR_BIT: u32 = 1u32 << 9;
const HAS_TAG_BIT: u32 = 1u32 << 10;

fn char_sxp(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&CHARSXP.to_be_bytes());
    out.extend_from_slice(&(s.len() as i32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn elf_so_image() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    v.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]);
    v.extend_from_slice(&[0u8; 56]);
    v
}

fn rcpp_module_rds() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"X\n");
    out.extend_from_slice(&3i32.to_be_bytes());
    out.extend_from_slice(&0x04_05_00i32.to_be_bytes());
    out.extend_from_slice(&0x03_05_00i32.to_be_bytes());
    out.extend_from_slice(&5i32.to_be_bytes());
    out.extend_from_slice(b"UTF-8");

    out.extend_from_slice(&(VECSXP | HAS_ATTR_BIT).to_be_bytes());
    out.extend_from_slice(&2i32.to_be_bytes());

    out.extend_from_slice(&STRSXP.to_be_bytes());
    out.extend_from_slice(&3i32.to_be_bytes());
    char_sxp(&mut out, "Rcpp::CharacterVector");
    char_sxp(&mut out, "RcppExports");
    char_sxp(&mut out, "Hello, disrobe!");

    let so: Vec<u8> = elf_so_image();
    out.extend_from_slice(&RAWSXP.to_be_bytes());
    out.extend_from_slice(&(so.len() as i32).to_be_bytes());
    out.extend_from_slice(&so);

    out.extend_from_slice(&(LISTSXP | HAS_TAG_BIT).to_be_bytes());
    out.extend_from_slice(&SYMSXP.to_be_bytes());
    char_sxp(&mut out, "names");
    out.extend_from_slice(&STRSXP.to_be_bytes());
    out.extend_from_slice(&2i32.to_be_bytes());
    char_sxp(&mut out, "exports");
    char_sxp(&mut out, "dll");
    out.extend_from_slice(&NILVALUE_SXP.to_be_bytes());

    out
}

#[test]
fn plain_hello_rds_is_not_rcpp() {
    let obj: RdsObject = read_rds(HELLO_RDS).expect("parse");
    let fp: RcppFingerprint = fingerprint(&obj, HELLO_RDS);
    assert!(!fp.is_rcpp(), "non-Rcpp RDS must not be flagged");
    assert!(fp.embedded_images.is_empty());
}

#[test]
fn rcpp_module_blob_detects_markers_oracle() {
    let blob: Vec<u8> = rcpp_module_rds();
    assert_eq!(classify(&blob), Some(ScriptLang::R));
    let fp: RcppFingerprint = analyze_rcpp(&blob).expect("analyze rcpp");
    assert!(fp.is_rcpp(), "Rcpp markers must be detected: {fp:?}");
    assert!(fp.uses_rcpp);
    assert!(
        fp.class_markers
            .iter()
            .any(|m: &String| m.contains("Rcpp::")),
        "class marker Rcpp:: must be recovered: {:?}",
        fp.class_markers
    );
    assert!(
        fp.class_markers.iter().any(|m: &String| m == "RcppExports"),
        "RcppExports marker must be recovered: {:?}",
        fp.class_markers
    );
}

#[test]
fn rcpp_module_blob_extracts_and_routes_elf_oracle() {
    let blob: Vec<u8> = rcpp_module_rds();
    let fp: RcppFingerprint = analyze_rcpp(&blob).expect("analyze rcpp");
    assert_eq!(
        fp.embedded_images.len(),
        1,
        "exactly one embedded ELF must be carved: {:?}",
        fp.embedded_images
    );
    let image: &disrobe_pass_scriptlang::EmbeddedNativeImage = &fp.embedded_images[0];
    assert_eq!(image.format, NativeImageFormat::Elf);
    assert_eq!(
        image.route_pass_id, "disrobe-pass-native",
        "carved native image must route to the native pass interface"
    );
    assert_eq!(
        &image.bytes[..4],
        &[0x7f, b'E', b'L', b'F'],
        "carved bytes must begin at the real ELF magic"
    );
}
