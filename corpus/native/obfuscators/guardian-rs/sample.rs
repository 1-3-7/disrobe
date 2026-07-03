#[inline(never)]
#[no_mangle]
pub extern "C" fn classify(n: i32) -> i32 {
    let r: i32 = (n + 1).wrapping_mul(3) ^ 0x5a;
    r - n
}

fn main() {
    let x: i32 = std::hint::black_box(7);
    println!("classify={}", classify(x));
}
