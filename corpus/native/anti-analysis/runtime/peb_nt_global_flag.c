#include "common.h"

#define FLG_HEAP_DEBUG_BITS 0x70u

int main(void) {
    struct peb_view *view = peb();
#if defined(ARMED)
    view->nt_global_flag = FLG_HEAP_DEBUG_BITS;
#endif
    uint32_t nt_global_flag = view->nt_global_flag;
    if (nt_global_flag & FLG_HEAP_DEBUG_BITS) {
        report("peb_nt_global_flag", 1);
    } else {
        report("peb_nt_global_flag", 0);
    }
    return 0;
}
