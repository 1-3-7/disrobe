#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_js_deob::v8::nexe::{NEXE_FOOTER_MAGIC, NexeLocation, detect_nexe_suffix};
use disrobe_pass_js_deob::v8::pkg::{PkgLocation, detect_pkg_payload};
use disrobe_pass_js_deob::v8::sea::{
    SEA_MAGIC, SEA_RESOURCE_TAG_V1, SeaBlobLocation, carve_sea_payload, detect_node_sea_blob,
};

fn synth_sea_binary(payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0u8; 128];
    out.extend_from_slice(&SEA_RESOURCE_TAG_V1.to_le_bytes());
    let blob_size: u32 = u32::try_from(payload.len() + SEA_MAGIC.len()).unwrap();
    out.extend_from_slice(&blob_size.to_le_bytes());
    out.extend_from_slice(SEA_MAGIC);
    out.extend_from_slice(payload);
    out
}

#[test]
fn node_sea_blob_detected_and_carved() {
    let payload: &[u8] = b"console.log('sea-bundle');\n";
    let bytes: Vec<u8> = synth_sea_binary(payload);
    let loc: SeaBlobLocation = detect_node_sea_blob(&bytes).expect("sea detected");
    assert_eq!(
        usize::try_from(loc.blob_size).unwrap(),
        payload.len() + SEA_MAGIC.len()
    );
    let carved: Vec<u8> = carve_sea_payload(&bytes).expect("carve");
    assert!(carved.ends_with(payload));
}

#[test]
fn vercel_pkg_payload_offset_recovered_from_suffix() {
    const MARKER: &[u8] = b"PAYLOAD_POSITION";
    let mut bytes: Vec<u8> = vec![0u8; 1024];
    bytes[100..100 + MARKER.len()].copy_from_slice(MARKER);
    let payload_off: u64 = 512;
    let payload_size: u64 = 32;
    bytes.extend_from_slice(&payload_size.to_le_bytes());
    bytes.extend_from_slice(&payload_off.to_le_bytes());
    let loc: PkgLocation = detect_pkg_payload(&bytes).expect("pkg location");
    assert_eq!(loc.payload_size, payload_size);
    assert_eq!(loc.payload_offset, payload_off);
}

#[test]
fn nexe_footer_sizes_recovered_from_suffix() {
    let mut bytes: Vec<u8> = vec![0u8; 256];
    let code_len: u64 = 100;
    let resource_len: u64 = 50;
    let total: usize = usize::try_from(code_len + resource_len).unwrap();
    bytes.extend(std::iter::repeat_n(0u8, total));
    bytes.extend_from_slice(&code_len.to_le_bytes());
    bytes.extend_from_slice(&resource_len.to_le_bytes());
    bytes.extend_from_slice(NEXE_FOOTER_MAGIC);
    let loc: NexeLocation = detect_nexe_suffix(&bytes).expect("nexe");
    assert_eq!(loc.payload_size, code_len + resource_len);
}

#[test]
#[ignore = "BLOCKER: real Node SEA / pkg / nexe binaries are platform-specific Node fixtures (PE/ELF/Mach-O); building per-OS fixtures requires Node 18-24 toolchains in CI — defer to dedicated fixtures sprint"]
fn node_sea_carve_from_real_node_binary() {
    panic!("ignored: needs real Node SEA-built binary fixture");
}
