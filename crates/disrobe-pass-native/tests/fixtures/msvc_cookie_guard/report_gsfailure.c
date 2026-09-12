#include <stdint.h>

__declspec(noreturn) void __report_gsfailure(uintptr_t cookie);

__declspec(noinline) void invoke_report_gsfailure(uintptr_t cookie) {
    __report_gsfailure(cookie);
}
