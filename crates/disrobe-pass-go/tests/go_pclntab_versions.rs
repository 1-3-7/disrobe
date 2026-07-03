#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_go::{GoImage, PclntabVersion, locate_pclntab};

#[test]
fn pclntab_version_detected_for_normal() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let image: GoImage<'_> = GoImage::parse(&bytes).expect("parse");
    let loc = locate_pclntab(&image).expect("locate");
    assert!(matches!(
        loc.header.version,
        PclntabVersion::Go118 | PclntabVersion::Go120
    ));
    assert_eq!(loc.header.ptr_size, 8);
    assert!(loc.header.n_funcs > 100);
}

#[test]
fn pclntab_version_detected_for_stripped() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_STRIPPED);
    let image: GoImage<'_> = GoImage::parse(&bytes).expect("parse stripped");
    let loc = locate_pclntab(&image).expect("locate stripped");
    assert!(matches!(
        loc.header.version,
        PclntabVersion::Go118 | PclntabVersion::Go120
    ));
}

#[test]
fn version_label_covers_full_matrix() {
    assert_eq!(PclntabVersion::Go12.label(), "go1.2..go1.15");
    assert_eq!(PclntabVersion::Go116.label(), "go1.16..go1.17");
    assert_eq!(PclntabVersion::Go118.label(), "go1.18..go1.19");
    assert_eq!(PclntabVersion::Go120.label(), "go1.20..go1.25");
}

#[test]
fn pclntab_magic_table_complete() {
    use disrobe_pass_go::pclntab::{MAGIC_GO12, MAGIC_GO116, MAGIC_GO118, MAGIC_GO120};
    assert_eq!(
        PclntabVersion::from_magic(MAGIC_GO12).unwrap(),
        PclntabVersion::Go12
    );
    assert_eq!(
        PclntabVersion::from_magic(MAGIC_GO116).unwrap(),
        PclntabVersion::Go116
    );
    assert_eq!(
        PclntabVersion::from_magic(MAGIC_GO118).unwrap(),
        PclntabVersion::Go118
    );
    assert_eq!(
        PclntabVersion::from_magic(MAGIC_GO120).unwrap(),
        PclntabVersion::Go120
    );
    assert!(PclntabVersion::from_magic(0xdead_beef).is_err());
}
