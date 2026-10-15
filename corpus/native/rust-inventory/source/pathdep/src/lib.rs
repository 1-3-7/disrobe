#[inline(never)]
pub fn scale(value: u64, shift: usize) -> u64 {
    let factor: u64 = 1u64
        .checked_shl(u32::try_from(shift).expect("shift fits u32"))
        .expect("shift below 64");
    value.checked_mul(factor).expect("scaled value fits u64")
}
