#include <windows.h>

__declspec(dllexport) BOOL WINAPI SayHello(void *data, DWORD length) {
    return data != 0 || length == 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
    return instance != 0 || reason == 0 || reserved == 0;
}
