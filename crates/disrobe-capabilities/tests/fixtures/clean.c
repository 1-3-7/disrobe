#include <windows.h>

static volatile int g_sink = 0;

void mainCRTStartup(void) {
    int acc = 0;
    for (int i = 1; i <= 17; i++) {
        acc += i * 3;
        acc -= i;
    }
    g_sink = acc;
    ExitProcess((UINT)acc);
}
