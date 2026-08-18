#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_lossless
)]

use disrobe_pass_native::packers::{
    GoRuntimeEvidence, UpxGoChainOutput, scan_go_runtime, unpack_upx_go_chain,
};

const HELLO_NRV2B: &[u8] =
    include_bytes!("../../../corpus/native/packers/upx/hello.packed.nrv2b.exe");
const HELLO_ORIGINAL: &[u8] =
    include_bytes!("../../../corpus/native/packers/upx/hello.original.exe");

#[test]
fn upx_go_chain_unpacks_real_upx_fixture() {
    let out: UpxGoChainOutput =
        unpack_upx_go_chain(HELLO_NRV2B).expect("UPX-on-Go chain must unpack a valid UPX PE");
    assert!(
        !out.unpacked_image.is_empty(),
        "chain must yield a decompressed image"
    );
    assert!(
        out.adler_verified,
        "chain must preserve the UPX UCL adler32 integrity check"
    );
    println!(
        "hello: unpacked={}B adler_verified={} go_markers={} is_go={}",
        out.unpacked_image.len(),
        out.adler_verified,
        out.go_evidence.marker_count(),
        out.is_go_binary
    );
}

#[test]
fn c_upx_fixture_is_not_misclassified_as_go() {
    let out: UpxGoChainOutput = unpack_upx_go_chain(HELLO_NRV2B).expect("unpack hello");
    assert!(
        !out.is_go_binary,
        "the committed hello fixture is a C binary; the Go-runtime classifier must not flag it (got {} markers)",
        out.go_evidence.marker_count()
    );
}

fn pe_section_raw(image: &[u8], name: &[u8]) -> Option<(usize, usize)> {
    let pe_off: usize =
        u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]) as usize;
    let nsec: usize = u16::from_le_bytes([image[pe_off + 6], image[pe_off + 7]]) as usize;
    let optsz: usize = u16::from_le_bytes([image[pe_off + 0x14], image[pe_off + 0x15]]) as usize;
    let secoff: usize = pe_off + 0x18 + optsz;
    for i in 0..nsec {
        let entry: usize = secoff + 0x28 * i;
        if &image[entry..entry + name.len()] == name {
            let vsize: usize = u32::from_le_bytes([
                image[entry + 8],
                image[entry + 9],
                image[entry + 10],
                image[entry + 11],
            ]) as usize;
            let raw_off: usize = u32::from_le_bytes([
                image[entry + 20],
                image[entry + 21],
                image[entry + 22],
                image[entry + 23],
            ]) as usize;
            return Some((raw_off, vsize));
        }
    }
    None
}

#[test]
fn chain_recovered_text_is_byte_identical_to_original() {
    let out: UpxGoChainOutput = unpack_upx_go_chain(HELLO_NRV2B).expect("unpack hello");
    let Some((text_raw, text_vsize)): Option<(usize, usize)> =
        pe_section_raw(HELLO_ORIGINAL, b".text")
    else {
        eprintln!("skip: original .text not located");
        return;
    };
    assert!(
        out.unpacked_image.len() >= text_vsize,
        "recovered image must hold the full .text"
    );
    let original_text: &[u8] = &HELLO_ORIGINAL[text_raw..text_raw + text_vsize];
    let recovered_text: &[u8] = &out.unpacked_image[0..text_vsize];
    assert_eq!(
        recovered_text, original_text,
        "chain-recovered .text must be byte-identical to the original (filter reversed by the in-house unpacker)"
    );
}

#[test]
fn go_classifier_negative_control_on_empty_image() {
    let ev: GoRuntimeEvidence = scan_go_runtime(&[]);
    assert_eq!(ev.marker_count(), 0);
    assert!(!ev.is_go());
}

#[test]
fn synthetic_go_runtime_markers_classify_as_go() {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&[0xF1, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x08]);
    buf.extend_from_slice(b"go1.22.3 runtime.morestack_noctxt Go build ID: x");
    let ev: GoRuntimeEvidence = scan_go_runtime(&buf);
    assert!(
        ev.is_go(),
        "gopclntab + version + morestack + build-id must classify as Go (got {} markers)",
        ev.marker_count()
    );
}

#[test]
#[ignore = "fixture: no UPX-packed Go binary in corpus/native/packers/upx (and rg/git UPX \
            fixtures use a relocated-magic UPX variant the in-house packheader parser does not \
            key on); a UPX-packed+unpacked Go fixture pair is required to witness the positive \
            end-to-end Go classification path. Do not download samples."]
fn upx_packed_go_binary_positive_path_pending_fixture() {
    panic!("staged for a real UPX-packed Go fixture pair");
}
