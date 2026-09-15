pub use disrobe_core::entropy::shannon_entropy_bits;
use serde::Serialize;

pub const ENTROPY_WINDOW_4K: usize = 4096;
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct EntropyBlock {
    pub index: usize,
    pub offset_start: usize,
    pub offset_end: usize,
    pub len: usize,
    pub entropy: f64,
    pub high: bool,
}

#[must_use]
pub fn windowed_entropy(bytes: &[u8], window: usize) -> Vec<EntropyBlock> {
    if bytes.is_empty() || window == 0 {
        return Vec::new();
    }
    let block_count: usize = bytes.len().div_ceil(window);
    let mut blocks: Vec<EntropyBlock> = Vec::with_capacity(block_count);
    for (index, chunk) in bytes.chunks(window).enumerate() {
        let offset_start: usize = index * window;
        let offset_end: usize = offset_start + chunk.len();
        let entropy: f64 = shannon_entropy_bits(chunk);
        blocks.push(EntropyBlock {
            index,
            offset_start,
            offset_end,
            len: chunk.len(),
            entropy,
            high: entropy >= HIGH_ENTROPY_THRESHOLD,
        });
    }
    blocks
}

#[must_use]
pub fn locate_high_entropy(bytes: &[u8], window: usize, threshold: f64) -> Vec<EntropyBlock> {
    windowed_entropy(bytes, window)
        .into_iter()
        .filter(|b: &EntropyBlock| b.entropy >= threshold)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{EntropyBlock, HIGH_ENTROPY_THRESHOLD, shannon_entropy_bits, windowed_entropy};

    #[test]
    fn all_zeros_window_is_zero_bits() {
        let h: f64 = shannon_entropy_bits(&[0u8; 4096]);
        assert!((h - 0.0).abs() < 1e-12, "expected 0.0 bits, got {h}");
    }

    #[test]
    fn uniform_256_window_is_eight_bits() {
        let window: Vec<u8> = (0..4096).map(|i: usize| (i & 0xff) as u8).collect();
        let h: f64 = shannon_entropy_bits(&window);
        assert!((h - 8.0).abs() < 1e-9, "expected 8.0 bits, got {h}");
    }

    #[test]
    fn two_symbol_50_50_window_is_one_bit() {
        let mut window: Vec<u8> = Vec::with_capacity(4096);
        window.extend(std::iter::repeat_n(0x00u8, 2048));
        window.extend(std::iter::repeat_n(0xffu8, 2048));
        let h: f64 = shannon_entropy_bits(&window);
        assert!((h - 1.0).abs() < 1e-12, "expected 1.0 bit, got {h}");
    }

    #[test]
    fn empty_and_zero_window_yield_empty() {
        assert!(windowed_entropy(&[], 4096).is_empty());
        assert!(windowed_entropy(&[0u8; 10], 0).is_empty());
    }

    #[test]
    fn partial_tail_window_covers_remainder() {
        let blocks: Vec<EntropyBlock> = windowed_entropy(&[0u8; 5000], 4096);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1].len, 904);
        assert_eq!(blocks[1].offset_start, 4096);
        assert_eq!(blocks[1].offset_end, 5000);
    }

    #[test]
    fn high_flag_tracks_named_threshold() {
        let window: Vec<u8> = (0..4096).map(|i: usize| (i & 0xff) as u8).collect();
        let blocks: Vec<EntropyBlock> = windowed_entropy(&window, 4096);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].entropy >= HIGH_ENTROPY_THRESHOLD);
        assert!(blocks[0].high);
    }
}
