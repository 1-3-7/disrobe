#include <windows.h>

static const char g_marker[] = "placeholder-marker-1";

void mainCRTStartup(void) {
    volatile unsigned long v0 = 0x1000;
    volatile unsigned long v1 = 0x1001;
    volatile unsigned long v2 = 0x1002;
    volatile unsigned long v3 = 0x1003;
    volatile const char *s = g_marker;
    ExitProcess((UINT)(v0 + v1 + v2 + v3 + (unsigned long)s[0]));
}
