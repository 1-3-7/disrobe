#[must_use]
pub fn shannon_entropy_bits(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts: [u64; 256] = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total: f64 = usize_to_f64(bytes.len());
    let mut bits: f64 = 0.0;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p: f64 = u64_to_f64(count) / total;
        bits = p.mul_add(-p.log2(), bits);
    }
    bits
}

#[allow(clippy::cast_precision_loss)]
const fn usize_to_f64(n: usize) -> f64 {
    n as f64
}

#[allow(clippy::cast_precision_loss)]
const fn u64_to_f64(n: u64) -> f64 {
    n as f64
}

#[cfg(test)]
mod tests {
    use super::shannon_entropy_bits;

    #[test]
    fn an_empty_input_carries_no_information() {
        assert!((shannon_entropy_bits(&[]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_single_repeated_byte_carries_no_information() {
        let bits: f64 = shannon_entropy_bits(&[0x41u8; 4096]);
        assert!(bits.abs() < 1e-12, "expected 0.0 bits, got {bits}");
    }

    #[test]
    fn two_equally_likely_symbols_carry_one_bit() {
        let mut data: Vec<u8> = Vec::with_capacity(4096);
        data.extend(std::iter::repeat_n(0x00u8, 2048));
        data.extend(std::iter::repeat_n(0xffu8, 2048));
        let bits: f64 = shannon_entropy_bits(&data);
        assert!((bits - 1.0).abs() < 1e-12, "expected 1.0 bit, got {bits}");
    }

    #[test]
    fn a_uniform_byte_distribution_carries_eight_bits() {
        let data: Vec<u8> = (0..4096).map(|i: usize| (i & 0xff) as u8).collect();
        let bits: f64 = shannon_entropy_bits(&data);
        assert!((bits - 8.0).abs() < 1e-9, "expected 8.0 bits, got {bits}");
    }

    #[test]
    fn a_skewed_distribution_lands_between_the_extremes() {
        let mut data: Vec<u8> = vec![0x00u8; 4000];
        data.extend(std::iter::repeat_n(0x01u8, 96));
        let bits: f64 = shannon_entropy_bits(&data);
        assert!(
            bits > 0.0 && bits < 1.0,
            "a rare second symbol lands strictly between zero and one bit, got {bits}"
        );
    }
}
