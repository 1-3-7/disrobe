#include <windows.h>

static volatile int g_marker = 0;

void NTAPI on_tls(PVOID hModule, DWORD reason, PVOID reserved) {
    (void)hModule;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent()) {
            g_marker = 0xDEAD;
        } else {
            g_marker = 0xBEEF;
        }
    }
}

#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK p_tls_cb = on_tls;

int main(void) {
    return g_marker;
}
