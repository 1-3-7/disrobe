#![no_std]

#[no_mangle]
pub unsafe extern "C" fn rust_bounds_guard(
    index: usize,
    len: usize,
    values: *const u64,
) -> u64 {
    let values = unsafe { core::slice::from_raw_parts(values, len) };
    values[index] + 1
}
