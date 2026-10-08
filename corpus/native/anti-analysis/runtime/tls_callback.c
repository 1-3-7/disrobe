#include "common.h"

static volatile int g_tls_ran = 0;
static volatile int g_tls_saw_debugger = 0;

static void NTAPI tls_probe(PVOID module, DWORD reason, PVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_tls_ran = 1;
        if (peb()->being_debugged) {
            g_tls_saw_debugger = 1;
        }
    }
}

#if defined(_WIN64)
__attribute__((section(".CRT$XLB"), used)) const PIMAGE_TLS_CALLBACK tls_probe_entry = tls_probe;
#else
__attribute__((section(".CRT$XLB"), used)) const PIMAGE_TLS_CALLBACK tls_probe_entry = tls_probe;
#endif

__thread int tls_anchor = 7;

int main(void) {
    if (!g_tls_ran) {
        printf("tls callback did not run\n");
        return 2;
    }
    report("tls_callback", g_tls_saw_debugger);
    return tls_anchor == 7 ? 0 : 1;
}
