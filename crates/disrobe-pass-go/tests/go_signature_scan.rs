#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use disrobe_pass_go::pclntab::signature_scan_pclntab;
use disrobe_pass_go::{GoAnalysis, GoImage, analyze, locate_pclntab};

/// Stomp the four pclntab magic bytes (garble-style) while leaving the rest of the
/// header intact, then confirm the signature scan reconstructs the table and the
/// full analysis recovers the same function and type counts as the un-stomped binary.
#[test]
fn signature_scan_recovers_magic_stomped_pclntab() {
    let Some(clean): Option<Vec<u8>> = common::fixture_or_skip(common::HELLO_NORMAL) else {
        return;
    };
    let baseline: GoAnalysis = analyze(&clean).expect("baseline analyze");
    let baseline_funcs: usize = baseline.symbols.funcs.len();
    let baseline_named: usize = baseline
        .typemeta
        .types
        .iter()
        .filter(|t| t.name.is_some())
        .count();
    assert!(baseline_funcs > 100, "baseline must have a real pclntab");

    let off: usize = common::find_pclntab_offset(&clean).expect("locate magic in file");
    let mut stomped: Vec<u8> = clean;
    stomped[off..off + 4].copy_from_slice(&[0xde, 0xad, 0xbe, 0x5f]);

    let image: GoImage<'_> = GoImage::parse(&stomped).expect("parse stomped");
    assert!(
        locate_pclntab(&image).is_ok(),
        "locate_pclntab must fall through to the signature scan and succeed"
    );
    let located = signature_scan_pclntab(&image).expect("signature scan must reconstruct pclntab");
    assert!(located.header.n_funcs as usize >= baseline_funcs.saturating_sub(8));

    let recovered: GoAnalysis = analyze(&stomped).expect("analyze stomped");
    assert_eq!(
        recovered.symbols.funcs.len(),
        baseline_funcs,
        "func recovery must match the un-stomped binary"
    );
    let recovered_named: usize = recovered
        .typemeta
        .types
        .iter()
        .filter(|t| t.name.is_some())
        .count();
    assert_eq!(
        recovered_named, baseline_named,
        "type-name recovery must match the un-stomped binary"
    );
    assert!(
        recovered
            .symbols
            .funcs
            .iter()
            .any(|f| f.name == "runtime.main"),
        "recovered funcname table must contain real symbols"
    );
}

/// A pure-garbage buffer with a stray magic-like run must never be promoted to a
/// pclntab: the structural scoring rejects it.
#[test]
fn signature_scan_rejects_coincidental_magic() {
    let mut junk: Vec<u8> = vec![0x41u8; 8192];
    junk[0..2].copy_from_slice(b"MZ");
    for i in (64..8000).step_by(64) {
        junk[i..i + 4].copy_from_slice(&[0xf1, 0xff, 0xff, 0xff]);
        junk[i + 6] = 1;
        junk[i + 7] = 8;
    }
    let Ok(image): Result<GoImage<'_>, _> = GoImage::parse(&junk) else {
        return;
    };
    assert!(
        signature_scan_pclntab(&image).is_err(),
        "coincidental magic runs must not validate as a pclntab"
    );
}
