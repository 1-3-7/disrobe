#![cfg(target_arch = "wasm32")]
use core::sync::atomic::{AtomicU64, Ordering};

static STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

#[inline]
fn next_u64() -> u64 {
    let z0: u64 = STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let mut z: u64 = z0.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    if dest.is_null() {
        if len == 0 {
            return Ok(());
        }
        return Err(getrandom::Error::UNEXPECTED);
    }
    let mut offset: usize = 0;
    while offset < len {
        let chunk: [u8; 8] = next_u64().to_le_bytes();
        let take: usize = core::cmp::min(8, len - offset);
        unsafe {
            core::ptr::copy_nonoverlapping(chunk.as_ptr(), dest.add(offset), take);
        }
        offset += take;
    }
    Ok(())
}
