#[inline]
pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    memchr_subslice(haystack, needle)
}

#[inline]
fn memchr_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first: u8 = needle[0];
    let mut start: usize = 0usize;
    while start + needle.len() <= haystack.len() {
        let rel: usize = haystack[start..].iter().position(|&b| b == first)?;
        let abs: usize = start + rel;
        if abs + needle.len() > haystack.len() {
            return None;
        }
        if &haystack[abs..abs + needle.len()] == needle {
            return Some(abs);
        }
        start = abs + 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn find_subslice_basic_hit() {
        assert_eq!(find_subslice(b"hello world", b"world"), Some(6));
    }

    #[test]
    fn find_subslice_no_match() {
        assert_eq!(find_subslice(b"abc", b"xyz"), None);
    }

    #[test]
    fn find_subslice_empty_needle_returns_none() {
        assert_eq!(find_subslice(b"abc", b""), None);
    }

    #[test]
    fn find_subslice_needle_longer_than_haystack() {
        assert_eq!(find_subslice(b"abc", b"abcd"), None);
    }

    #[test]
    fn find_subslice_handles_overlapping_first_byte() {
        let hay: &[u8; 4] = b"aaab";
        assert_eq!(find_subslice(hay, b"aab"), Some(1));
        assert_eq!(find_subslice(hay, b"aaab"), Some(0));
        assert_eq!(find_subslice(hay, b"baaa"), None);
    }
}
