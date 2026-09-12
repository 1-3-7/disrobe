use crc32fast::Hasher;

#[must_use]
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut hasher: Hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_empty_input() {
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
    }

    #[test]
    fn crc32_known_sentence() {
        assert_eq!(
            crc32_ieee(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }
}
