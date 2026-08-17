#include <arm_acle.h>
#include <stdint.h>

uint32_t crc_ieee_b(uint32_t accumulator, uint8_t value) {
    return __crc32b(accumulator, value);
}

uint32_t crc_ieee_h(uint32_t accumulator, uint16_t value) {
    return __crc32h(accumulator, value);
}

uint32_t crc_ieee_w(uint32_t accumulator, uint32_t value) {
    return __crc32w(accumulator, value);
}

uint32_t crc_ieee_x(uint32_t accumulator, uint64_t value) {
    return __crc32d(accumulator, value);
}

uint32_t crc_castagnoli_b(uint32_t accumulator, uint8_t value) {
    return __crc32cb(accumulator, value);
}

uint32_t crc_castagnoli_h(uint32_t accumulator, uint16_t value) {
    return __crc32ch(accumulator, value);
}

uint32_t crc_castagnoli_w(uint32_t accumulator, uint32_t value) {
    return __crc32cw(accumulator, value);
}

uint32_t crc_castagnoli_x(uint32_t accumulator, uint64_t value) {
    return __crc32cd(accumulator, value);
}

uint32_t crc_ieee_check(void) {
    uint32_t accumulator = __crc32d(0xffffffffu, 0x3837363534333231ull);
    return __crc32b(accumulator, 0x39u);
}

uint32_t crc_castagnoli_check(void) {
    uint32_t accumulator = __crc32cd(0xffffffffu, 0x3837363534333231ull);
    return __crc32cb(accumulator, 0x39u);
}
