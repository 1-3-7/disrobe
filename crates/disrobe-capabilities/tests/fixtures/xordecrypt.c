#include <windows.h>

static unsigned char g_buf[64] = {
    0x14, 0x2f, 0x77, 0x6a, 0x11, 0x55, 0x18, 0x42,
    0x3d, 0x29, 0x6c, 0x71, 0x09, 0x1a, 0x33, 0x6e,
};

void mainCRTStartup(void) {
    volatile unsigned char *p = g_buf;
    unsigned char key = 0x5a;
    for (unsigned long i = 0; i < sizeof(g_buf); i++) {
        p[i] = (unsigned char)(p[i] ^ key);
        key = (unsigned char)((key << 1) | (key >> 7));
    }
    ExitProcess((UINT)p[0]);
}
