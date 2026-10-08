#ifndef DISROBE_RUNTIME_CHECK_COMMON_H
#define DISROBE_RUNTIME_CHECK_COMMON_H

#include <stdint.h>
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h>
#endif

static void report(const char *check, int debugged) {
    printf("check=%s result=%s\n", check, debugged ? "debugged" : "clean");
}

#if defined(_WIN64)
struct peb_view {
    uint8_t inherited_address_space;
    uint8_t read_image_file_exec_options;
    uint8_t being_debugged;
    uint8_t pad0[0xBC - 3];
    uint32_t nt_global_flag;
};

static inline __attribute__((always_inline)) unsigned char *peb_base(void) {
    unsigned char *peb;
    __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
}
#elif defined(_WIN32)
struct peb_view {
    uint8_t inherited_address_space;
    uint8_t read_image_file_exec_options;
    uint8_t being_debugged;
    uint8_t pad0[0x68 - 3];
    uint32_t nt_global_flag;
};

static inline __attribute__((always_inline)) unsigned char *peb_base(void) {
    unsigned char *peb;
    __asm__ volatile("mov %%fs:0x30, %0" : "=r"(peb));
    return peb;
}
#endif

#if defined(_WIN32)
static inline __attribute__((always_inline)) struct peb_view *peb(void) {
    return (struct peb_view *)peb_base();
}
#endif

#endif
