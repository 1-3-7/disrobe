#include <windows.h>

void mainCRTStartup(void) {
    HANDLE h = CreateFileW(L"C:\\disrobe-out.bin", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        const char msg[] = "disrobe write-file oracle payload";
        DWORD written = 0;
        WriteFile(h, msg, (DWORD)sizeof(msg), &written, NULL);
        CloseHandle(h);
    }
    ExitProcess(0);
}
