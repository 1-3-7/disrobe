#include <windows.h>

static volatile unsigned char g_flag = 0xAB;
static unsigned char g_buf[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

__declspec(noinline) unsigned char example_helper(unsigned char v) {
    return (unsigned char)(v + 1);
}

void mainCRTStartup(void) {
    unsigned char a = g_flag;
    unsigned char b;
    unsigned char h = example_helper(a);
    g_buf[2] = h;
    if (a == 0xAB) {
        b = (unsigned char)(a + 0x2A);
        g_buf[0] = b;
    } else {
        b = (unsigned char)(a ^ 0x37);
        g_buf[1] = b;
    }
    ExitProcess((UINT)b);
}
