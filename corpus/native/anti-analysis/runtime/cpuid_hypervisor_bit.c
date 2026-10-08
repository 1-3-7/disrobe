#include "common.h"

#define HYPERVISOR_PRESENT_BIT 0x80000000u

int main(void) {
    uint32_t eax = 1;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    uint32_t hypervisor = ecx & HYPERVISOR_PRESENT_BIT;
    if (hypervisor) {
        report("cpuid_hypervisor_bit", 1);
    } else {
        report("cpuid_hypervisor_bit", 0);
    }
    return (ebx | edx) == 0 ? 1 : 0;
}
