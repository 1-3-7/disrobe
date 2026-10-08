#include "common.h"

static volatile int g_debugged = 1;

static LONG WINAPI trap_handler(EXCEPTION_POINTERS *pointers) {
    if (pointers->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
#if !defined(ARMED)
        g_debugged = 0;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    AddVectoredExceptionHandler(1, trap_handler);
    g_debugged = 1;
    __asm__ volatile("int $0x2d\n\tnop");
    if (g_debugged) {
        report("int2d_trap", 1);
    } else {
        report("int2d_trap", 0);
    }
    return 0;
}
