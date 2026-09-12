__declspec(dllimport) void *GetModuleHandleA(const char *name);
__declspec(dllimport) unsigned long GetLastError(void);
__declspec(dllimport) unsigned int GetTickCount(void);
__declspec(dllimport) void ExitProcess(unsigned int code);

void _start(void) {
    void *h = GetModuleHandleA(0);
    unsigned long e = GetLastError();
    unsigned int t = GetTickCount();
    unsigned int code = (unsigned int)(unsigned long long)h + e + t;
    ExitProcess(code);
}
