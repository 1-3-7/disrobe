use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use disrobe_pass_mobile::Error;
use disrobe_pass_mobile::axml;

struct PeakTrackingAlloc;

static PEAK_SINGLE_ALLOC: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for PeakTrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        PEAK_SINGLE_ALLOC.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: PeakTrackingAlloc = PeakTrackingAlloc;

const ALLOC_CEILING: usize = 64 * 1024;

fn axml_with_string_count(string_count: u32) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0x0003u16.to_le_bytes());
    bytes.extend_from_slice(&0x0008u16.to_le_bytes());
    bytes.extend_from_slice(&38u32.to_le_bytes());
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001cu16.to_le_bytes());
    bytes.extend_from_slice(&0x001cu32.to_le_bytes());
    bytes.extend_from_slice(&string_count.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 2]);
    bytes
}

#[test]
fn axml_inflated_string_count_reserves_by_remaining_bytes() {
    let bytes: Vec<u8> = axml_with_string_count(u32::MAX);
    PEAK_SINGLE_ALLOC.store(0, Ordering::Relaxed);
    let result: Result<axml::AxmlDocument, Error> = axml::parse(&bytes);
    let peak: usize = PEAK_SINGLE_ALLOC.load(Ordering::Relaxed);
    assert!(
        matches!(result, Err(Error::AxmlTruncated)),
        "a string pool declaring u32::MAX offsets over 2 bytes must truncate, got {result:?}"
    );
    assert!(
        peak <= ALLOC_CEILING,
        "a declared u32::MAX string offsets over 2 remaining bytes reserved {peak} bytes in one allocation"
    );
}
