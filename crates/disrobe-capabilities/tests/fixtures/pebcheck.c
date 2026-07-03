#include <windows.h>
#include <intrin.h>

void mainCRTStartup(void) {
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    unsigned char being_debugged = peb[2];
    ExitProcess((UINT)being_debugged);
}
