#include "common.h"

int main(void) {
    struct peb_view *view = peb();
#if defined(ARMED)
    view->being_debugged = 1;
#endif
    unsigned char being_debugged = view->being_debugged;
    if (being_debugged) {
        report("peb_being_debugged", 1);
    } else {
        report("peb_being_debugged", 0);
    }
    return 0;
}
