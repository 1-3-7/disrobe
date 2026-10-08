#include "common.h"

int main(void) {
#if defined(ARMED)
    peb()->being_debugged = 1;
#endif
    if (IsDebuggerPresent()) {
        report("is_debugger_present", 1);
    } else {
        report("is_debugger_present", 0);
    }
    return 0;
}
