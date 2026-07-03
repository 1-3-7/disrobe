#include <windows.h>

void mainCRTStartup(void) {
    unsigned char buf[16];
    *(unsigned int *)(buf + 0) = 0x656a6e69;
    *(unsigned int *)(buf + 4) = 0x64657463;
    *(unsigned int *)(buf + 8) = 0;
    volatile unsigned char sink = buf[1];
    ExitProcess((UINT)sink);
}
