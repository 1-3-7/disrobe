#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn classify_local(x: i32) -> i32 {
    let mut state: i32 = 0;
    let mut acc: i32 = 0;
    loop {
        match state {
            0 => {
                acc = x.wrapping_add(1);
                state = if x > 10 { 1 } else { 2 };
            }
            1 => {
                acc = acc.wrapping_mul(3);
                state = 3;
            }
            2 => {
                acc = acc.wrapping_sub(7);
                state = 3;
            }
            _ => return acc,
        }
    }
}
