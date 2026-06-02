#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    Packer, UpxMethod, UpxUnpackOutput, detect_packers, packed_upx_elf64_marker, unpack_upx,
};

const PACKED_NRV2B: &[u8] =
    include_bytes!("../../../corpus/native/packers/upx/hello.packed.nrv2b.exe");
const ORIGINAL: &[u8] = include_bytes!("../../../corpus/native/packers/upx/hello.original.exe");

#[test]
fn baked_upx_elf64_marker_detected() {
    let bytes: Vec<u8> = packed_upx_elf64_marker();
    let hits = detect_packers(&bytes);
    assert!(hits.iter().any(|h| h.packer == Packer::Upx));
}

fn pe_section_raw(image: &[u8], name: &[u8]) -> (usize, usize) {
    let pe_off: usize =
        u32::from_le_bytes([image[0x3c], image[0x3d], image[0x3e], image[0x3f]]) as usize;
    assert_eq!(&image[pe_off..pe_off + 4], b"PE\0\0", "valid PE signature");
    let coff: usize = pe_off + 4;
    let num_sections: usize = u16::from_le_bytes([image[coff + 2], image[coff + 3]]) as usize;
    let opt_size: usize = u16::from_le_bytes([image[coff + 16], image[coff + 17]]) as usize;
    let sect_table: usize = coff + 20 + opt_size;
    for i in 0..num_sections {
        let entry: usize = sect_table + i * 40;
        let raw_name: &[u8] = &image[entry..entry + 8];
        if raw_name.starts_with(name) {
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
            return (raw_off, vsize);
        }
    }
    panic!("section {name:?} not found in PE");
}

#[test]
fn nrv2b_real_fixture_roundtrip_byte_identical_modulo_padding() {
    let out: UpxUnpackOutput =
        unpack_upx(PACKED_NRV2B).expect("NRV2B unpack must succeed on committed fixture");
    assert_eq!(out.method, UpxMethod::Nrv2b);
    assert!(
        out.adler_verified,
        "UCL adler32 over recovered image must match PackHeader u_adler"
    );
    assert!(out.block_count >= 1);
    assert_eq!(
        out.filter_id, 0x49,
        "fixture uses the x86-64 CT call filter 0x49"
    );

    let (text_raw, text_vsize): (usize, usize) = pe_section_raw(ORIGINAL, b".text");
    let original_text: &[u8] = &ORIGINAL[text_raw..text_raw + text_vsize];
    let recovered_text: &[u8] = &out.recovered_image[0..text_vsize];
    assert_eq!(
        recovered_text, original_text,
        "recovered .text must be byte-identical to the original (filter 0x49 reversed)"
    );
}

#[test]
fn non_upx_input_is_rejected() {
    let buf: Vec<u8> = vec![0x55u8; 4096];
    assert!(unpack_upx(&buf).is_err());
}
