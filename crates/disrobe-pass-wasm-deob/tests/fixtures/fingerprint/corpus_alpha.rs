#![no_std]
#![no_main]

#[panic_handler]
fn on_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[inline(never)]
fn fnv1a_hash(ptr: *const u8, len: usize) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    let mut i: usize = 0;
    while i < len {
        let byte: u8 = unsafe { *ptr.add(i) };
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        i += 1;
    }
    hash
}

#[inline(never)]
fn sum_range(n: u32) -> u64 {
    let mut acc: u64 = 0;
    let mut i: u32 = 0;
    while i < n {
        acc = acc.wrapping_add((i as u64).wrapping_mul(i as u64));
        i += 1;
    }
    acc
}

#[inline(never)]
fn fib(n: u32) -> u64 {
    if n < 2 {
        return n as u64;
    }
    fib(n - 1).wrapping_add(fib(n - 2))
}

#[inline(never)]
fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t: u32 = b;
        b = a % b;
        a = t;
    }
    a
}

#[inline(never)]
fn popcount_manual(mut x: u32) -> u32 {
    let mut count: u32 = 0;
    while x != 0 {
        count += x & 1;
        x >>= 1;
    }
    count
}

#[inline(never)]
fn clamp_i32(x: i32, lo: i32, hi: i32) -> i32 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

#[inline(never)]
fn hash_and_clamp(ptr: *const u8, len: usize, lo: i32, hi: i32) -> i32 {
    let h: u32 = fnv1a_hash(ptr, len);
    clamp_i32(h as i32, lo, hi)
}

#[inline(never)]
fn alpha_only_mix(a: u32, b: u32, c: u32) -> u32 {
    let mut acc: u32 = a ^ b.rotate_left(9);
    acc = acc.rotate_left(7).wrapping_add(c);
    acc = acc.rotate_right(11) ^ a;
    acc.wrapping_mul(0x9e37_79b1)
}

#[unsafe(no_mangle)]
pub extern "C" fn alpha_entry(ptr: *const u8, len: usize, seed: u32) -> u32 {
    let mut total: u32 = fnv1a_hash(ptr, len);
    total = total.wrapping_add(sum_range(seed) as u32);
    total = total.wrapping_add(fib(seed & 0x1f) as u32);
    total = total.wrapping_add(gcd(total | 1, seed | 1));
    total = total.wrapping_add(popcount_manual(total));
    total = total.wrapping_add(clamp_i32(total as i32, seed as i32, seed as i32 ^ 0x7fff) as u32);
    total = total.wrapping_add(hash_and_clamp(ptr, len, seed as i32, seed as i32 | 0x3ff) as u32);
    total = total.wrapping_add(alpha_only_mix(total, seed, len as u32));
    total
}
