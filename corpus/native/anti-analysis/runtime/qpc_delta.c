#include "common.h"

#define QPC_THRESHOLD_TICKS 50000ll

int main(void) {
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    QueryPerformanceCounter(&start);
#if defined(ARMED)
    Sleep(40);
#endif
    volatile int sink = 0;
    for (int i = 0; i < 16; i++) {
        sink += i;
    }
    QueryPerformanceCounter(&end);
    long long delta = end.QuadPart - start.QuadPart;
    if (delta > QPC_THRESHOLD_TICKS) {
        report("qpc_delta", 1);
    } else {
        report("qpc_delta", 0);
    }
    return sink == 120 ? 0 : 1;
}
