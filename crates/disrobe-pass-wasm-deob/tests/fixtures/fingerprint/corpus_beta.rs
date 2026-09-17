#![no_std]
#![no_main]

#[panic_handler]
fn on_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[inline(never)]
fn matrix_trace(m0: u32, m1: u32, m2: u32, m3: u32) -> u32 {
    let mut trace: u32 = m0.wrapping_add(m3);
    trace = trace.wrapping_sub(m1 & m2);
    trace ^= m0.rotate_left(3);
    trace.wrapping_mul(0x27d4_eb2f)
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
fn beta_only_scan(ptr: *const u8, len: usize) -> u32 {
    let mut best: u32 = 0;
    let mut i: usize = 0;
    while i < len {
        let byte: u32 = unsafe { *ptr.add(i) } as u32;
        if byte > best {
            best = byte;
        }
        i += 1;
    }
    best.wrapping_mul(3).wrapping_add(len as u32)
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

#[unsafe(no_mangle)]
pub extern "C" fn beta_entry(ptr: *const u8, len: usize, seed: u32) -> u32 {
    let mut total: u32 = matrix_trace(seed, seed ^ 0x1234, seed.rotate_left(5), len as u32);
    total = total.wrapping_add(gcd(total | 1, seed | 3));
    total = total.wrapping_add(beta_only_scan(ptr, len));
    total = total.wrapping_add(fnv1a_hash(ptr, len));
    total = total.wrapping_add(clamp_i32(total as i32, seed as i32, seed as i32 | 0x7ff) as u32);
    total = total.wrapping_add(sum_range(seed) as u32);
    total = total.wrapping_add(fib(seed & 0x1f) as u32);
    total
}
