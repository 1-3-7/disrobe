use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NameStrategy {
    Clean,
    Hex,
    Alphanum,
    Homoglyph,
    FixedLength,
}

const ENTROPY_THRESHOLD: f64 = 3.5;
const LENGTH_VARIANCE_THRESHOLD: f64 = 0.1;

pub fn classify_export_strategy(names: &[String]) -> NameStrategy {
    if names.is_empty() {
        return NameStrategy::Clean;
    }

    if names.iter().any(|n| contains_homoglyph_codepoint(n)) {
        return NameStrategy::Homoglyph;
    }

    let entropies: Vec<f64> = names
        .iter()
        .map(|n| shannon_entropy_bits(n.as_bytes()))
        .collect();
    let entropy_count: f64 = usize_to_f64(entropies.len());
    let mean_entropy: f64 = entropies.iter().sum::<f64>() / entropy_count;

    if mean_entropy >= ENTROPY_THRESHOLD {
        if names.iter().all(|n| n.bytes().all(is_hex_char)) {
            return NameStrategy::Hex;
        }
        if names.iter().all(|n| n.bytes().all(is_alphanum_char)) {
            return NameStrategy::Alphanum;
        }
    }

    let lens: Vec<f64> = names.iter().map(|n| usize_to_f64(n.len())).collect();
    let lens_count: f64 = usize_to_f64(lens.len());
    let mean_len: f64 = lens.iter().sum::<f64>() / lens_count;
    if mean_len > 0.0 {
        let variance: f64 = lens.iter().map(|l| (l - mean_len).powi(2)).sum::<f64>() / lens_count;
        let coeff: f64 = variance.sqrt() / mean_len;
        if coeff < LENGTH_VARIANCE_THRESHOLD && names.len() >= 3 {
            return NameStrategy::FixedLength;
        }
    }

    NameStrategy::Clean
}

fn shannon_entropy_bits(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts: [u32; 256] = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total: f64 = usize_to_f64(bytes.len());
    let mut h: f64 = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p: f64 = f64::from(c) / total;
        h -= p * p.log2();
    }
    h
}

#[allow(clippy::cast_precision_loss)]
const fn usize_to_f64(n: usize) -> f64 {
    n as f64
}

const fn is_hex_char(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

const fn is_alphanum_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn contains_homoglyph_codepoint(s: &str) -> bool {
    s.chars().any(|c| {
        let n: u32 = c as u32;
        (0x00F3..=0x00F8).contains(&n)
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_clean() {
        assert_eq!(classify_export_strategy(&[]), NameStrategy::Clean);
    }

    #[test]
    fn normal_english_names_return_clean() {
        let names: Vec<String> = vec![
            "write".to_owned(),
            "read".to_owned(),
            "open".to_owned(),
            "close".to_owned(),
            "main".to_owned(),
        ];
        assert_eq!(classify_export_strategy(&names), NameStrategy::Clean);
    }

    #[test]
    fn high_entropy_hex_returns_hex() {
        let names: Vec<String> = vec![
            "36c4abdf9f8e2bcd".to_owned(),
            "a1b2c3d4deadbeef".to_owned(),
            "0123456789abcdef".to_owned(),
            "f0e1d2c3b4a59687".to_owned(),
            "8a7b6c5d4e3f2a1b".to_owned(),
        ];
        assert_eq!(classify_export_strategy(&names), NameStrategy::Hex);
    }

    #[test]
    fn high_entropy_alphanum_returns_alphanum() {
        let names: Vec<String> = vec![
            "Xq7rPzKvMnB8jHqL".to_owned(),
            "wTr9KsXyPz3MjVcN".to_owned(),
            "ABcd1234EFgh5678".to_owned(),
            "ZyXwVuTsRqPoNmLk".to_owned(),
            "9876543210ABCDEF".to_owned(),
        ];
        assert_eq!(classify_export_strategy(&names), NameStrategy::Alphanum);
    }

    #[test]
    fn homoglyph_codepoints_return_homoglyph() {
        let names: Vec<String> = vec![
            "\u{00F3}\u{00F4}\u{00F5}".to_owned(),
            "regular_name".to_owned(),
        ];
        assert_eq!(classify_export_strategy(&names), NameStrategy::Homoglyph);
    }

    #[test]
    fn fixed_length_returns_fixed_length() {
        let names: Vec<String> = vec![
            "abcde".to_owned(),
            "fghij".to_owned(),
            "klmno".to_owned(),
            "pqrst".to_owned(),
        ];
        assert_eq!(classify_export_strategy(&names), NameStrategy::FixedLength);
    }

    #[test]
    fn shannon_entropy_of_uniform_is_high() {
        let e: f64 = shannon_entropy_bits(b"abcdefghij");
        assert!(e > 3.2, "uniform alphabet entropy should be >3.2; got {e}");
    }

    #[test]
    fn shannon_entropy_of_constant_is_zero() {
        let e: f64 = shannon_entropy_bits(b"aaaaaaaaaa");
        assert!(e < 0.01, "constant byte entropy should be ~0; got {e}");
    }
}
