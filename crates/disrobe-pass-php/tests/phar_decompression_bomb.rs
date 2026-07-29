#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    unreachable_pub,
    dead_code
)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{PHAR_FLAG_DEFLATE, PharFixtureEntry};
use disrobe_pass_php::{
    Error, PHAR_DECOMPRESS_CAP, PharArchive, extract_phar_entry, parse_phar,
    phar_decompress_ceiling,
};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

const BOMB_CHUNK: usize = 64 * 1024;
const BOMB_CHUNKS: usize = 1024;
const BOMB_EXPANDED: usize = BOMB_CHUNK * BOMB_CHUNKS;
const ALLOCATION_ALLOWANCE: usize = 4 * 1024 * 1024;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

struct PeakTracking;

impl PeakTracking {
    fn charge(size: usize) {
        let live: usize = LIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;
        PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
    }

    fn release(size: usize) {
        LIVE_BYTES.fetch_sub(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for PeakTracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr: *mut u8 = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            Self::charge(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr: *mut u8 = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            Self::charge(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        Self::release(layout.size());
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let fresh: *mut u8 = unsafe { System.realloc(ptr, layout, new_size) };
        if !fresh.is_null() {
            Self::release(layout.size());
            Self::charge(new_size);
        }
        fresh
    }
}

#[global_allocator]
static ALLOCATOR: PeakTracking = PeakTracking;

fn deflate_bomb() -> Vec<u8> {
    let zeros: Vec<u8> = vec![0u8; BOMB_CHUNK];
    let mut encoder: DeflateEncoder<Vec<u8>> = DeflateEncoder::new(Vec::new(), Compression::best());
    for _ in 0..BOMB_CHUNKS {
        encoder.write_all(&zeros).expect("bomb chunk compresses");
    }
    encoder.finish().expect("bomb stream finishes")
}

fn expanded_len(stream: &[u8]) -> u64 {
    let mut decoder: DeflateDecoder<&[u8]> = DeflateDecoder::new(stream);
    std::io::copy(&mut decoder, &mut std::io::sink()).expect("bomb stream inflates")
}

#[test]
fn declared_length_past_what_the_compressed_bytes_support_is_refused_without_allocating() {
    let bomb: Vec<u8> = deflate_bomb();
    assert_eq!(
        expanded_len(&bomb),
        BOMB_EXPANDED as u64,
        "fixture must be a real deflate bomb, graded by flate2 directly"
    );
    assert!(
        bomb.len() < 256 * 1024,
        "bomb stream should stay tiny on disk, got {} bytes",
        bomb.len()
    );

    let declared: u32 = u32::try_from(BOMB_EXPANDED).expect("declared size fits u32");
    let phar: Vec<u8> = common::build_phar_with_entries(
        &common::default_phar_stub(),
        &[PharFixtureEntry {
            name: "bomb.php",
            stored: &bomb,
            declared_uncompressed: declared,
            crc32: 0,
            flags: PHAR_FLAG_DEFLATE,
        }],
    );
    let archive: PharArchive = parse_phar(&phar).expect("bomb archive parses");

    let ceiling: usize = phar_decompress_ceiling(bomb.len());
    assert!(
        ceiling < BOMB_EXPANDED,
        "ceiling {ceiling} must sit below the {BOMB_EXPANDED}-byte expansion"
    );
    assert!(ceiling <= PHAR_DECOMPRESS_CAP);

    let baseline: usize = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(baseline, Ordering::Relaxed);
    let outcome: Result<Vec<u8>, Error> = extract_phar_entry(&archive, &phar, "bomb.php");
    let peak: usize = PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);

    match outcome {
        Err(Error::PharDeclaredSizeImplausible {
            name,
            declared: reported,
            stored,
            ceiling: reported_ceiling,
        }) => {
            assert_eq!(name, "bomb.php");
            assert_eq!(reported, declared);
            assert_eq!(stored, u32::try_from(bomb.len()).expect("stored fits u32"));
            assert_eq!(reported_ceiling, ceiling);
        }
        other => panic!("expected a refused declared length, got {other:?}"),
    }
    assert!(
        peak < ALLOCATION_ALLOWANCE,
        "refusing the bomb allocated {peak} bytes, past the {ALLOCATION_ALLOWANCE}-byte allowance; \
         the {BOMB_EXPANDED}-byte expansion must never be materialized"
    );
    println!(
        "bomb stream {} bytes, refusal peak {peak} bytes",
        bomb.len()
    );
}
