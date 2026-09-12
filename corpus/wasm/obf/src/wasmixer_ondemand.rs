#![no_std]
#![no_main]

#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub static mut ENC: [u8; 30] = [
    0x2f, 0x22, 0x38, 0x39, 0x24, 0x29, 0x2e, 0x64, 0x3c, 0x2a, 0x38, 0x26, 0x64, 0x24, 0x25,
    0x66, 0x2f, 0x2e, 0x26, 0x2a, 0x25, 0x2f, 0x66, 0x2f, 0x2e, 0x28, 0x39, 0x32, 0x3b, 0x3f,
];

#[unsafe(no_mangle)]
pub extern "C" fn dec_load(off: i32, len: i32) -> i32 {
    let base: *mut u8 = (&raw mut ENC) as *mut u8;
    let p: *mut u8 = unsafe { base.offset(off as isize) };
    let mut i: i32 = 0;
    while i < len {
        unsafe {
            let c: u8 = *p.offset(i as isize);
            *p.offset(i as isize) = c ^ 0x4b;
        }
        i += 1;
    }
    p as i32
}
