#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern float recovered_truncxfsf2(uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t);

static uint32_t zig_013_subnormal_bits(uint64_t significand, uint16_t exponent) {
    const uint64_t fraction = significand & UINT64_C(0x7fffffffffffffff);
    const unsigned int shift = 16256U - (unsigned int)exponent;
    if (shift > 63U) {
        return 0;
    }
    const uint64_t sticky = (fraction << shift) != 0;
    const uint64_t denormalized = (fraction >> shift) | sticky;
    const uint64_t remainder = denormalized & UINT64_C(0xffffffffff);
    uint32_t result = (uint32_t)(denormalized >> 40);
    if (remainder > UINT64_C(0x8000000000)
        || (remainder == UINT64_C(0x8000000000) && (result & 1U) != 0)) {
        ++result;
    }
    return result;
}

int main(void) {
    static const struct {
        uint64_t significand;
        uint16_t exponent;
        uint32_t expected;
    } cases[] = {
        {UINT64_C(0x8000000000000000), 16383, UINT32_C(0x3f800000)},
        {UINT64_C(0x8000007fffffffff), 16383, UINT32_C(0x3f800000)},
        {UINT64_C(0x8000008000000000), 16383, UINT32_C(0x3f800000)},
        {UINT64_C(0x8000008000000001), 16383, UINT32_C(0x3f800001)},
        {UINT64_C(0x8000010000000000), 16383, UINT32_C(0x3f800001)},
        {UINT64_C(0x8000010000000001), 16383, UINT32_C(0x3f800001)},
        {UINT64_C(0x8000017fffffffff), 16383, UINT32_C(0x3f800001)},
        {UINT64_C(0x8000018000000000), 16383, UINT32_C(0x3f800002)},
        {UINT64_C(0x8000018000000001), 16383, UINT32_C(0x3f800002)},
        {UINT64_C(0xffffffffffffffff), 16383, UINT32_C(0x40000000)},
        {UINT64_C(0x8000000000000000), 16257, UINT32_C(0x00800000)},
        {UINT64_C(0x8000000000000000), 16256, UINT32_C(0x00400000)},
        {UINT64_C(0x8000020000000001), 16256, UINT32_C(0x00400001)},
        {UINT64_C(0x8000030000000000), 16256, UINT32_C(0x00400002)},
        {UINT64_C(0x8000030000000001), 16256, UINT32_C(0x00400002)},
        {UINT64_C(0x8000000000000000), 16234, UINT32_C(0x00000001)},
        {UINT64_C(0x8000000000000000), 16233, UINT32_C(0x00000000)},
        {UINT64_C(0x8000000000000001), 16233, UINT32_C(0x00000001)},
        {UINT64_C(0x802fffffffffffff), 16243, UINT32_C(0x00000201)},
        {UINT64_C(0x8030000000000000), 16243, UINT32_C(0x00000201)},
        {UINT64_C(0x8030000000000001), 16243, UINT32_C(0x00000201)}
    };
    unsigned int count = 0;
    for (unsigned int sign = 0; sign < 2; ++sign) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            const float value = recovered_truncxfsf2(0, 0, 0, 0, 0, 0,
                cases[i].significand, (uint64_t)cases[i].exponent | ((uint64_t)sign << 15));
            uint32_t actual = 0;
            memcpy(&actual, &value, sizeof(actual));
            const uint32_t magnitude = cases[i].exponent >= 16257U
                ? cases[i].expected
                : zig_013_subnormal_bits(cases[i].significand, cases[i].exponent);
            const uint32_t expected = magnitude | ((uint32_t)sign << 31);
            if (actual != expected) {
                printf("case=%zu sign=%u actual=%08x expected=%08x\n",
                    i, sign, (unsigned int)actual, (unsigned int)expected);
                return 1;
            }
            ++count;
        }
    }
    printf("%u\n", count);
    return 0;
}
