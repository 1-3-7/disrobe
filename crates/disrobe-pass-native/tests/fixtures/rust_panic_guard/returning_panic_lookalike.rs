#![no_std]

#[inline(never)]
fn panic_bounds_check(index: usize, len: usize, location: usize) -> usize {
    index + len + location
}

#[no_mangle]
pub extern "C" fn returning_panic_lookalike(index: usize) -> usize {
    panic_bounds_check(index, 3, 1) + 1
}
