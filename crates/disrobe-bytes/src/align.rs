macro_rules! align_pair {
    ($up:ident, $down:ident, $ty:ty, $wide:ty) => {
        #[inline]
        #[must_use]
        pub const fn $up(value: $ty, align: $ty) -> $ty {
            if align == 0 {
                return value;
            }
            let wide_value: $wide = value as $wide;
            let wide_align: $wide = align as $wide;
            let aligned: $wide = wide_value.div_ceil(wide_align) * wide_align;
            let narrow_max: $wide = <$ty>::MAX as $wide;
            if aligned > narrow_max {
                <$ty>::MAX
            } else {
                aligned as $ty
            }
        }

        #[inline]
        #[must_use]
        pub const fn $down(value: $ty, align: $ty) -> $ty {
            if align == 0 {
                return value;
            }
            value - (value % align)
        }
    };
}

align_pair!(align_up_u32, align_down_u32, u32, u64);
align_pair!(align_up_u64, align_down_u64, u64, u128);
align_pair!(align_up_usize, align_down_usize, usize, u128);

#[cfg(test)]
mod tests {
    use super::{align_down_u32, align_up_u32, align_up_u64, align_up_usize};

    #[test]
    fn align_up_rounds_to_next_multiple() {
        assert_eq!(align_up_u32(0, 16), 0);
        assert_eq!(align_up_u32(1, 16), 16);
        assert_eq!(align_up_u32(16, 16), 16);
        assert_eq!(align_up_u32(17, 16), 32);
    }

    #[test]
    fn align_up_handles_non_power_of_two() {
        assert_eq!(align_up_u32(10, 3), 12);
        assert_eq!(align_up_u32(9, 3), 9);
    }

    #[test]
    fn align_up_zero_align_is_identity() {
        assert_eq!(align_up_u32(42, 0), 42);
        assert_eq!(align_up_u64(u64::MAX, 0), u64::MAX);
    }

    #[test]
    fn align_up_saturates_instead_of_overflowing() {
        assert_eq!(align_up_u32(u32::MAX, 2), u32::MAX);
        assert_eq!(align_up_u64(u64::MAX, 2), u64::MAX);
    }

    #[test]
    fn align_down_zero_align_is_identity() {
        assert_eq!(align_down_u32(42, 0), 42);
    }

    #[test]
    fn align_down_rounds_to_previous_multiple() {
        assert_eq!(align_down_u32(17, 16), 16);
        assert_eq!(align_down_u32(16, 16), 16);
        assert_eq!(align_down_u32(15, 16), 0);
    }

    #[test]
    fn align_up_usize_matches_u32_on_shared_range() {
        assert_eq!(align_up_usize(17, 16), 32);
    }
}
