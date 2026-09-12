#[inline]
#[must_use]
pub fn bounded_element_capacity(count: u64, elem_bytes: usize, remaining: usize) -> usize {
    let per_element_ceiling: usize = (remaining / elem_bytes.max(1)).saturating_add(1);
    usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(per_element_ceiling)
}

#[cfg(test)]
mod tests {
    use super::bounded_element_capacity;

    #[test]
    fn caps_an_untrusted_count_to_the_buffer_ceiling() {
        assert_eq!(bounded_element_capacity(u64::MAX, 8, 16), 16 / 8 + 1);
        assert_eq!(bounded_element_capacity(u64::MAX, 4, 16), 16 / 4 + 1);
    }

    #[test]
    fn preserves_a_legitimate_small_count() {
        assert_eq!(bounded_element_capacity(3, 8, 4096), 3);
        assert_eq!(bounded_element_capacity(0, 8, 4096), 0);
    }

    #[test]
    fn zero_element_bytes_is_treated_as_one() {
        assert_eq!(bounded_element_capacity(u64::MAX, 0, 16), 17);
    }

    #[test]
    fn empty_buffer_admits_at_most_one_element() {
        assert_eq!(bounded_element_capacity(u64::MAX, 8, 0), 1);
        assert_eq!(bounded_element_capacity(0, 8, 0), 0);
    }

    #[test]
    fn a_count_beyond_usize_saturates_before_the_min() {
        let ceiling: usize = (1024usize / 8).saturating_add(1);
        assert_eq!(bounded_element_capacity(u64::MAX, 8, 1024), ceiling);
    }
}
