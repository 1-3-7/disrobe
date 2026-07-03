#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::fixtures::{minimal_lx, minimal_ne};
use disrobe_pass_native::{DetectedFormat, NativeFormat, detect_format};

const REAL_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
const REAL_LX: &[u8] = include_bytes!("../../../corpus/native/formats/hello_lx.exe");

#[test]
fn ne_fixture_classified() {
    let d = detect_format(&minimal_ne()).expect("ne");
    assert_eq!(d.kind, NativeFormat::Ne);
}

#[test]
fn lx_fixture_classified() {
    let d = detect_format(&minimal_lx()).expect("lx");
    assert_eq!(d.kind, NativeFormat::Lx);
}

fn new_header_sig(image: &[u8]) -> [u8; 2] {
    let lfanew: usize =
        u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]) as usize;
    [image[lfanew], image[lfanew + 1]]
}

#[test]
fn real_legacy_binary_walk() {
    assert_eq!(
        &new_header_sig(REAL_NE),
        b"NE",
        "the real OpenWatcom build must carry a Win16 NE new-header signature"
    );
    let ne: DetectedFormat = detect_format(REAL_NE).expect("detect real NE");
    assert_eq!(
        ne.kind,
        NativeFormat::Ne,
        "a real Win16 NE executable must classify as Ne; notes={:?}",
        ne.notes
    );

    assert_eq!(
        &new_header_sig(REAL_LX),
        b"LX",
        "the real OpenWatcom build must carry an OS/2 LX new-header signature"
    );
    let lx: DetectedFormat = detect_format(REAL_LX).expect("detect real LX");
    assert_eq!(
        lx.kind,
        NativeFormat::Lx,
        "a real OS/2 LX executable must classify as Lx; notes={:?}",
        lx.notes
    );

    assert!(
        REAL_NE.len() < 256 * 1024 && REAL_LX.len() < 256 * 1024,
        "fixtures under 256KB budget"
    );
}
