#include "common.h"

#define TICK_THRESHOLD_MS 10u

int main(void) {
    DWORD start = GetTickCount();
#if defined(ARMED)
    Sleep(40);
#endif
    volatile int sink = 0;
    for (int i = 0; i < 16; i++) {
        sink += i;
    }
    DWORD end = GetTickCount();
    DWORD delta = end - start;
    if (delta > TICK_THRESHOLD_MS) {
        report("tick_count_delta", 1);
    } else {
        report("tick_count_delta", 0);
    }
    return sink == 120 ? 0 : 1;
}
