use super::{IndexBound, is_contiguous_low_mask};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValueSet {
    base: u64,
    stride: u64,
    count: u64,
}

impl ValueSet {
    const fn new(base: u64, stride: u64, count: u64) -> Self {
        Self {
            base,
            stride: if stride == 0 { 1 } else { stride },
            count,
        }
    }

    #[cfg(feature = "cfg-recovery")]
    pub(crate) const fn singleton(value: u64) -> Self {
        Self {
            base: value,
            stride: 1,
            count: 1,
        }
    }

    #[cfg(feature = "cfg-recovery")]
    pub(crate) const fn as_constant(self) -> Option<u64> {
        if self.count == 1 {
            Some(self.base)
        } else {
            None
        }
    }

    pub(crate) const fn min(self) -> u64 {
        self.base
    }

    pub(crate) const fn max(self) -> u64 {
        self.base
            .saturating_add(self.stride.saturating_mul(self.count.saturating_sub(1)))
    }

    pub(crate) const fn count(self) -> u64 {
        self.count
    }

    pub(crate) fn iter(self) -> impl Iterator<Item = u64> {
        let base: u64 = self.base;
        let stride: u64 = self.stride;
        (0..self.count).map(move |step: u64| base.wrapping_add(stride.wrapping_mul(step)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VsaResult {
    Exact(ValueSet),
    Empty,
    Unbounded,
    Unsupported,
    SolverRequired,
}

const fn strided_mask(mask: u64) -> Option<(u64, u64)> {
    if mask == 0 {
        return Some((1, 0));
    }
    let trailing: u32 = mask.trailing_zeros();
    let shifted: u64 = mask >> trailing;
    if is_contiguous_low_mask(shifted) {
        Some((1u64 << trailing, mask))
    } else {
        None
    }
}

const fn round_up_to_multiple(value: u64, stride: u64) -> Option<u64> {
    if stride <= 1 {
        return Some(value);
    }
    let remainder: u64 = value % stride;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(stride - remainder)
    }
}

pub(crate) fn index_value_set(bounds: &[IndexBound], ceiling: u64) -> VsaResult {
    let mut lo: u64 = 0;
    let mut hi: u64 = ceiling;
    let mut bounded_above: bool = false;
    let mut stride: u64 = 1;
    let mut mask_seen: bool = false;
    let mut has_disequality: bool = false;
    for bound in bounds {
        match bound {
            IndexBound::UnsignedAtMost(value) => {
                hi = hi.min(*value);
                bounded_above = true;
            }
            IndexBound::UnsignedLessThan(value) => {
                let Some(top): Option<u64> = value.checked_sub(1) else {
                    return VsaResult::Empty;
                };
                hi = hi.min(top);
                bounded_above = true;
            }
            IndexBound::UnsignedAtLeast(value) => {
                lo = lo.max(*value);
            }
            IndexBound::Mask(mask) => {
                if mask_seen {
                    return VsaResult::Unsupported;
                }
                mask_seen = true;
                let Some((mask_stride, mask_max)): Option<(u64, u64)> = strided_mask(*mask) else {
                    return VsaResult::Unsupported;
                };
                stride = mask_stride;
                hi = hi.min(mask_max);
                bounded_above = true;
            }
            IndexBound::NotEqual(_) => {
                has_disequality = true;
            }
        }
    }
    if has_disequality {
        return VsaResult::SolverRequired;
    }
    if !bounded_above {
        return VsaResult::Unbounded;
    }
    if lo > hi {
        return VsaResult::Empty;
    }
    let Some(first): Option<u64> = round_up_to_multiple(lo, stride) else {
        return VsaResult::Empty;
    };
    if first > hi {
        return VsaResult::Empty;
    }
    let last: u64 = (hi / stride) * stride;
    let count: u64 = (last - first) / stride + 1;
    VsaResult::Exact(ValueSet::new(first, stride, count))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn exact(bounds: &[IndexBound], ceiling: u64) -> ValueSet {
        match index_value_set(bounds, ceiling) {
            VsaResult::Exact(set) => set,
            other => panic!("expected an exact value set, got {other:?}"),
        }
    }

    #[test]
    fn compare_guard_is_a_dense_interval() {
        let set: ValueSet = exact(&[IndexBound::UnsignedAtMost(5)], u64::from(u32::MAX));
        assert_eq!((set.min(), set.max(), set.count()), (0, 5, 6));
        assert_eq!(set.iter().collect::<Vec<u64>>(), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn less_than_lowers_the_upper_bound() {
        let set: ValueSet = exact(&[IndexBound::UnsignedLessThan(4)], u64::from(u32::MAX));
        assert_eq!(set.iter().collect::<Vec<u64>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn contiguous_mask_is_dense_from_zero() {
        let set: ValueSet = exact(&[IndexBound::Mask(0x7)], u64::from(u32::MAX));
        assert_eq!(set.count(), 8);
        assert_eq!(
            set.iter().collect::<Vec<u64>>(),
            (0..=7).collect::<Vec<u64>>()
        );
    }

    #[test]
    fn strided_mask_has_a_power_of_two_stride() {
        let set: ValueSet = exact(&[IndexBound::Mask(0xE)], u64::from(u32::MAX));
        assert_eq!((set.min(), set.max(), set.count()), (0, 14, 8));
        assert_eq!(
            set.iter().collect::<Vec<u64>>(),
            vec![0, 2, 4, 6, 8, 10, 12, 14]
        );
    }

    #[test]
    fn wider_strided_mask_strides_by_four() {
        let set: ValueSet = exact(&[IndexBound::Mask(0xC)], u64::from(u32::MAX));
        assert_eq!(set.iter().collect::<Vec<u64>>(), vec![0, 4, 8, 12]);
    }

    #[test]
    fn strided_mask_meets_a_lower_bound() {
        let set: ValueSet = exact(
            &[IndexBound::Mask(0xE), IndexBound::UnsignedAtLeast(5)],
            u64::from(u32::MAX),
        );
        assert_eq!(set.iter().collect::<Vec<u64>>(), vec![6, 8, 10, 12, 14]);
    }

    #[test]
    fn non_strided_mask_is_unsupported() {
        assert_eq!(
            index_value_set(&[IndexBound::Mask(0xA)], u64::from(u32::MAX)),
            VsaResult::Unsupported
        );
    }

    #[test]
    fn two_masks_are_unsupported() {
        assert_eq!(
            index_value_set(
                &[IndexBound::Mask(0x7), IndexBound::Mask(0x3)],
                u64::from(u32::MAX)
            ),
            VsaResult::Unsupported
        );
    }

    #[test]
    fn no_upper_bound_is_unbounded() {
        assert_eq!(
            index_value_set(&[IndexBound::UnsignedAtLeast(2)], u64::from(u32::MAX)),
            VsaResult::Unbounded
        );
    }

    #[test]
    fn crossed_bounds_are_empty() {
        assert_eq!(
            index_value_set(
                &[
                    IndexBound::UnsignedAtMost(1),
                    IndexBound::UnsignedAtLeast(5)
                ],
                u64::from(u32::MAX)
            ),
            VsaResult::Empty
        );
    }

    #[test]
    fn disequality_requires_the_solver() {
        assert_eq!(
            index_value_set(
                &[IndexBound::UnsignedAtMost(3), IndexBound::NotEqual(1)],
                u64::from(u32::MAX)
            ),
            VsaResult::SolverRequired
        );
    }

    #[test]
    fn zero_mask_pins_the_index_to_zero() {
        let set: ValueSet = exact(&[IndexBound::Mask(0)], u64::from(u32::MAX));
        assert_eq!((set.min(), set.max(), set.count()), (0, 0, 1));
    }

    #[test]
    fn less_than_zero_is_empty() {
        assert_eq!(
            index_value_set(&[IndexBound::UnsignedLessThan(0)], u64::from(u32::MAX)),
            VsaResult::Empty
        );
    }
}
