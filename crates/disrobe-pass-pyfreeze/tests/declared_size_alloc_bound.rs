#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

struct PeakTrackingAlloc;

static PEAK_SINGLE_ALLOC: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for PeakTrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size: usize = layout.size();
        let mut observed: usize = PEAK_SINGLE_ALLOC.load(Ordering::Relaxed);
        while size > observed {
            match PEAK_SINGLE_ALLOC.compare_exchange_weak(
                observed,
                size,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: PeakTrackingAlloc = PeakTrackingAlloc;

const FORGED_UNCOMPRESSED: u64 = 500 * 1024 * 1024;
const ALLOC_CEILING: usize = 64 * 1024 * 1024;

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn forge_zip_with_lying_uncompressed_size() -> Vec<u8> {
    let members: [(&str, &[u8], u32); 2] = [
        (
            "_bootstrap/environment.json",
            br#"{"entry_point":"app:main","shiv_version":"1.0"}"#,
            0,
        ),
        ("payload.bin", b"", FORGED_UNCOMPRESSED as u32),
    ];

    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();

    for (name, data, declared_uncompressed) in members {
        let local_offset: u32 = out.len() as u32;
        let crc: u32 = crc32(data);
        let comp_size: u32 = data.len() as u32;

        put_u32(&mut out, 0x0403_4B50);
        put_u16(&mut out, 20);
        put_u16(&mut out, 0);
        put_u16(&mut out, 0);
        put_u16(&mut out, 0);
        put_u16(&mut out, 0);
        put_u32(&mut out, crc);
        put_u32(&mut out, comp_size);
        put_u32(&mut out, declared_uncompressed);
        put_u16(&mut out, name.len() as u16);
        put_u16(&mut out, 0);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        put_u32(&mut central, 0x0201_4B50);
        put_u16(&mut central, 20);
        put_u16(&mut central, 20);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u32(&mut central, crc);
        put_u32(&mut central, comp_size);
        put_u32(&mut central, declared_uncompressed);
        put_u16(&mut central, name.len() as u16);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u32(&mut central, 0);
        put_u32(&mut central, local_offset);
        central.extend_from_slice(name.as_bytes());
    }

    let cd_offset: u32 = out.len() as u32;
    let cd_size: u32 = central.len() as u32;
    out.extend_from_slice(&central);

    put_u32(&mut out, 0x0605_4B50);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, members.len() as u16);
    put_u16(&mut out, members.len() as u16);
    put_u32(&mut out, cd_size);
    put_u32(&mut out, cd_offset);
    put_u16(&mut out, 0);
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask: u32 = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[test]
fn shiv_does_not_preallocate_on_lying_declared_uncompressed_size() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"#!/usr/bin/env python3\n");
    blob.extend_from_slice(&forge_zip_with_lying_uncompressed_size());

    let purpose: String = format!(
        "disrobe-shiv-alloc-bound-{}-{}",
        std::process::id(),
        blob.len()
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let out: std::path::PathBuf = scratch.path().to_path_buf();

    PEAK_SINGLE_ALLOC.store(0, Ordering::Relaxed);
    let result = disrobe_pass_pyfreeze::shiv::detect_and_extract(&blob, Path::new("x.pyz"), &out);
    let peak: usize = PEAK_SINGLE_ALLOC.load(Ordering::Relaxed);
    assert!(
        result.is_ok(),
        "a structurally valid shiv with a lying declared size must still extract: {:?}",
        result.err()
    );
    assert!(
        peak < ALLOC_CEILING,
        "a tiny zip declaring a {FORGED_UNCOMPRESSED}-byte STORED entry forced a {peak}-byte single allocation; \
         the extractor must not pre-reserve based on the untrusted declared uncompressed size"
    );
}
