pub(crate) fn f32_operand(bits: u32) -> String {
    f32::from_bits(bits).to_string()
}

pub(crate) fn f64_operand(bits: u64) -> String {
    f64::from_bits(bits).to_string()
}
