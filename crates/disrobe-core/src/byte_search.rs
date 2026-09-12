use memchr::memmem;

#[inline]
#[must_use]
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    memmem::find(haystack, needle).is_some()
}

#[inline]
#[must_use]
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    memmem::find(haystack, needle)
}

#[cfg(test)]
mod tests {
    use super::{contains, find};

    fn windowed_contains_reference(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
    }

    fn find_subslice_reference(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || needle.len() > haystack.len() {
            return None;
        }
        haystack
            .windows(needle.len())
            .position(|w: &[u8]| w == needle)
    }

    const CASES: &[(&[u8], &[u8])] = &[
        (b"return(function(...)local v={", b"local v={"),
        (b"-- WeAreDevs header text", b"-- WeAreDevs"),
        (b"-- WeAreDevs header text", b"WRD_OBFUSCATOR"),
        (b"prefixNEEDLEsuffix", b"NEEDLE"),
        (b"NEEDLEsuffix", b"NEEDLE"),
        (b"prefixNEEDLE", b"NEEDLE"),
        (b"NEEDLE", b"NEEDLE"),
        (b"aaaaab", b"aab"),
        (b"abababab", b"abab"),
        (b"abc", b"abcd"),
        (b"", b"x"),
        (b"haystack-with-no-hit", b"zzz"),
        (b"\x00\x01\x02\x03", b"\x01\x02"),
    ];

    #[test]
    fn contains_matches_windowed_reference_for_nonempty_needles() {
        for &(haystack, needle) in CASES {
            assert_eq!(
                contains(haystack, needle),
                windowed_contains_reference(haystack, needle),
                "contains mismatch for haystack {haystack:?} needle {needle:?}"
            );
        }
    }

    #[test]
    fn find_matches_subslice_reference() {
        for &(haystack, needle) in CASES {
            assert_eq!(
                find(haystack, needle),
                find_subslice_reference(haystack, needle),
                "find mismatch for haystack {haystack:?} needle {needle:?}"
            );
        }
    }

    #[test]
    fn empty_needle_is_defined_not_found() {
        assert!(!contains(b"anything", b""));
        assert!(!contains(b"", b""));
        assert_eq!(find(b"anything", b""), None);
        assert_eq!(find(b"", b""), None);
    }

    #[test]
    fn needle_at_both_edges_and_overlap() {
        assert!(contains(b"xyxyxz", b"xy"));
        assert_eq!(find(b"xyxyxz", b"xy"), Some(0));
        assert_eq!(find(b"_xy", b"xy"), Some(1));
        assert_eq!(find(b"aaa", b"aa"), Some(0));
    }
}
