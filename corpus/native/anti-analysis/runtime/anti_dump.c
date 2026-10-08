#include "common.h"

#if defined(_WIN64)
#define PEB_LDR_OFFSET 0x18
#define PEB_IMAGE_BASE_OFFSET 0x10
#define LDR_IN_LOAD_ORDER_OFFSET 0x10
#define ENTRY_SIZE_OF_IMAGE_OFFSET 0x40
#else
#define PEB_LDR_OFFSET 0x0C
#define PEB_IMAGE_BASE_OFFSET 0x08
#define LDR_IN_LOAD_ORDER_OFFSET 0x0C
#define ENTRY_SIZE_OF_IMAGE_OFFSET 0x20
#endif

static uint32_t tamper_size_of_image(void) {
    unsigned char *peb = peb_base();
    unsigned char *ldr = *(unsigned char **)(peb + PEB_LDR_OFFSET);
    unsigned char *first_entry = *(unsigned char **)(ldr + LDR_IN_LOAD_ORDER_OFFSET);
    uint32_t *size_of_image = (uint32_t *)(first_entry + ENTRY_SIZE_OF_IMAGE_OFFSET);
    uint32_t before = *size_of_image;
    *size_of_image = 0x1000;
    return before;
}

static int erase_header(void) {
    unsigned char *peb = peb_base();
    unsigned char *image = *(unsigned char **)(peb + PEB_IMAGE_BASE_OFFSET);
    DWORD old_protect = 0;
    if (!VirtualProtect(image, 0x1000, PAGE_READWRITE, &old_protect)) {
        return 0;
    }
    for (size_t i = 0; i < 0x400; i++) {
        image[i] = 0;
    }
    return 1;
}

int main(void) {
    uint32_t before = tamper_size_of_image();
    int erased = erase_header();
    printf("check=anti_dump size_of_image_before=%#x header_erased=%d\n", (unsigned)before, erased);
    return 0;
}
