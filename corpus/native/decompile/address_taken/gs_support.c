#include <windows.h>
#include <intrin.h>

UINT_PTR __security_cookie = 0x00002B992DDFA232ULL;

__declspec(noinline) void __cdecl __security_check_cookie(UINT_PTR cookie)
{
    if (cookie != __security_cookie) {
        __fastfail(2);
    }
}

const IMAGE_LOAD_CONFIG_DIRECTORY64 _load_config_used = {
    .Size = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64),
    .SecurityCookie = (ULONGLONG)&__security_cookie,
};

EXCEPTION_DISPOSITION __GSHandlerCheck(PEXCEPTION_RECORD record, PVOID frame, PCONTEXT context, PVOID dispatcher)
{
    (void)record;
    (void)frame;
    (void)context;
    (void)dispatcher;
    return ExceptionContinueSearch;
}
