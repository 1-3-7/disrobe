#include "common.h"

int main(void) {
    BOOL present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present) && present) {
        report("check_remote_debugger_present", 1);
    } else {
        report("check_remote_debugger_present", 0);
    }
    return 0;
}
