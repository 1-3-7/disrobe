#[inline(never)]
pub fn weave(values: &[u32], index: usize) -> u32 {
    let picked: u32 = values[index % values.len()];
    picked.rotate_left(5) ^ 0x9e37_79b9
}
