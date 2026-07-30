#![allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod packer_fixture;

use disrobe_pass_native::{
    EntropyBlock, HIGH_ENTROPY_THRESHOLD, locate_high_entropy, shannon_entropy_bits,
    windowed_entropy,
};
use packer_fixture::{PackerFixture, load_fixture};

const WINDOW: usize = 4096;

fn upx_corpus(name: &str) -> Option<Vec<u8>> {
    load_fixture(PackerFixture {
        decoder: "UPX",
        family: "upx",
        name,
    })
}

fn mean(blocks: &[EntropyBlock]) -> f64 {
    if blocks.is_empty() {
        return 0.0;
    }
    blocks.iter().map(|b: &EntropyBlock| b.entropy).sum::<f64>() / blocks.len() as f64
}

#[test]
fn all_zeros_window_is_zero_bits() {
    let h: f64 = shannon_entropy_bits(&[0u8; WINDOW]);
    assert!((h - 0.0).abs() < 1e-12, "expected 0.0 bits, got {h}");
}

#[test]
fn uniform_256_window_is_eight_bits() {
    let window: Vec<u8> = (0..WINDOW).map(|i: usize| (i & 0xff) as u8).collect();
    let h: f64 = shannon_entropy_bits(&window);
    assert!((h - 8.0).abs() < 1e-9, "expected 8.0 bits, got {h}");
}

#[test]
fn two_symbol_50_50_window_is_one_bit() {
    let mut window: Vec<u8> = Vec::with_capacity(WINDOW);
    window.extend(std::iter::repeat_n(0x00u8, WINDOW / 2));
    window.extend(std::iter::repeat_n(0xffu8, WINDOW / 2));
    let h: f64 = shannon_entropy_bits(&window);
    assert!((h - 1.0).abs() < 1e-12, "expected 1.0 bit, got {h}");
}

#[test]
fn partial_tail_window_covers_remainder() {
    let blocks: Vec<EntropyBlock> = windowed_entropy(&[0u8; 5000], WINDOW);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[1].len, 904);
    assert_eq!(blocks[1].offset_start, 4096);
    assert_eq!(blocks[1].offset_end, 5000);
}

#[test]
fn packed_upx_surfaces_high_entropy_block() {
    let Some(bytes): Option<Vec<u8>> = upx_corpus("git.packed.upx.exe") else {
        return;
    };
    let high: Vec<EntropyBlock> = locate_high_entropy(&bytes, WINDOW, HIGH_ENTROPY_THRESHOLD);
    assert!(
        !high.is_empty(),
        "packed UPX surfaced no high-entropy block"
    );
    assert!(
        high.iter().any(|b: &EntropyBlock| b.entropy >= 7.5),
        "packed UPX has no block >= 7.5 bits/byte"
    );
}

#[test]
fn packed_mean_exceeds_unpacked() {
    let Some(packed): Option<Vec<u8>> = upx_corpus("git.packed.upx.exe") else {
        return;
    };
    let Some(unpacked): Option<Vec<u8>> = upx_corpus("git.unpacked.upx.exe") else {
        return;
    };
    let packed_mean: f64 = mean(&windowed_entropy(&packed, WINDOW));
    let unpacked_mean: f64 = mean(&windowed_entropy(&unpacked, WINDOW));
    assert!(
        packed_mean > unpacked_mean,
        "packed mean {packed_mean} should exceed unpacked mean {unpacked_mean}"
    );
}
