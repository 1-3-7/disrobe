unsigned long __stack_chk_guard = 0x5d3c9e17a4b2f068UL;

void __stack_chk_fail(void) {
    for (;;) {
    }
}

void stub_binder(void) __asm__("dyld_stub_binder");

void stub_binder(void) {
}
