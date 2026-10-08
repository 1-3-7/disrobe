#include "common.h"

static volatile int g_route = 0;

static LONG WINAPI route_handler(EXCEPTION_POINTERS *pointers) {
    if (pointers->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        g_route = 2;
#if defined(_WIN64)
        pointers->ContextRecord->Rip += 2;
#else
        pointers->ContextRecord->Eip += 2;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int divide(int numerator, int denominator) {
    int quotient;
    __asm__ volatile("xor %%edx, %%edx\n\tidivl %2" : "=a"(quotient) : "a"(numerator), "r"(denominator) : "edx");
    return quotient;
}

int main(void) {
    AddVectoredExceptionHandler(1, route_handler);
    g_route = 1;
    volatile int zero = 0;
    int quotient = divide(84, zero);
    (void)quotient;
    if (g_route == 2) {
        report("veh_control_flow", 0);
    } else {
        report("veh_control_flow", 1);
    }
    return 0;
}
