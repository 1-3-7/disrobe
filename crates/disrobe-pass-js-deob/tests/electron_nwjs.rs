#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;

use disrobe_pass_js_deob::v8::asar_listing::{ASAR_HEADER_PREFIX_LEN, AsarListing, list_asar};
use disrobe_pass_js_deob::v8::nwjs::{NwjsLocation, detect_nwjs_zip_suffix};

const fn align_up(value: usize, align: usize) -> usize {
    let rem: usize = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn synth_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut header: String = String::from(r#"{"files":{"#);
    let mut offset: u64 = 0;
    for (i, (name, body)) in files.iter().enumerate() {
        if i > 0 {
            header.push(',');
        }
        let size: usize = body.len();
        let _ = write!(header, r#""{name}":{{"size":{size},"offset":"{offset}"}}"#);
        offset += body.len() as u64;
    }
    header.push_str("}}");
    let header_bytes: &[u8] = header.as_bytes();
    let header_size: u32 = u32::try_from(header_bytes.len()).unwrap();
    let aligned: u32 = u32::try_from(align_up(header_bytes.len(), 4)).unwrap();
    let pickle_size: u32 = 8 + aligned;
    let outer_marker: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&outer_marker);
    out.extend_from_slice(&pickle_size.to_le_bytes());
    out.extend_from_slice(&outer_marker);
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(header_bytes);
    out.extend(std::iter::repeat_n(0u8, (aligned - header_size) as usize));
    for (_, body) in files {
        out.extend_from_slice(body);
    }
    out
}

#[test]
fn electron_asar_listing_with_multiple_entries() {
    let bytes: Vec<u8> = synth_asar(&[
        ("renderer.js", b"window.addEventListener('load', ()=>{})"),
        ("preload.js", b"contextBridge.exposeInMainWorld('api', {})"),
        ("package.json", b"{\"name\":\"electron-app\"}"),
    ]);
    let listing: AsarListing = list_asar(&bytes).expect("asar listing");
    assert_eq!(listing.entries.len(), 3);
    assert!(listing.data_offset >= ASAR_HEADER_PREFIX_LEN as u64);
    let names: Vec<&str> = listing.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(names.contains(&"renderer.js"));
    assert!(names.contains(&"preload.js"));
    assert!(names.contains(&"package.json"));
}

#[test]
fn nwjs_zip_suffix_eocd_detected_in_binary_tail() {
    const EOCD_SIG: u32 = 0x0605_4b50;
    let mut bytes: Vec<u8> = vec![0u8; 8192];
    let off: usize = bytes.len() - 22;
    bytes[off..off + 4].copy_from_slice(&EOCD_SIG.to_le_bytes());
    bytes[off + 12..off + 16].copy_from_slice(&200u32.to_le_bytes());
    bytes[off + 16..off + 20].copy_from_slice(&1000u32.to_le_bytes());
    let loc: NwjsLocation = detect_nwjs_zip_suffix(&bytes).expect("nwjs zip eocd");
    assert_eq!(loc.eocd_offset, off as u64);
    assert_eq!(loc.central_dir_size, 200);
    assert_eq!(loc.central_dir_offset, 1000);
}

#[test]
#[ignore = "BLOCKER: real Electron .asar shipping with full app needs upstream Electron build (large, license-incompat for fixture corpus); pure-Rust parse covered by other tests"]
fn electron_real_asar_from_packaged_app() {
    panic!("ignored: real-app fixture pending");
}
