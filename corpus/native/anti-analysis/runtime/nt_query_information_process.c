#include "common.h"

#define PROCESS_DEBUG_PORT 7u

extern LONG WINAPI NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);

int main(void) {
    ULONG_PTR debug_port = 0;
    ULONG returned = 0;
    int debugged = 0;
    LONG status = NtQueryInformationProcess(GetCurrentProcess(), PROCESS_DEBUG_PORT, &debug_port,
                                            sizeof(debug_port), &returned);
    if (status == 0 && debug_port != 0) {
        debugged = 1;
    }
    report("nt_query_information_process", debugged);
    return 0;
}
