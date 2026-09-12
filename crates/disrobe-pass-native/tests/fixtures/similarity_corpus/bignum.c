#include "corpus.h"

#define BN_LIMBS 8

u32 bn_add(u32 *dst, const u32 *a, const u32 *b, u32 n) {
    u64 carry = 0;
    for (u32 i = 0; i < n; i++) {
        u64 sum = (u64)a[i] + (u64)b[i] + carry;
        dst[i] = (u32)sum;
        carry = sum >> 32;
    }
    return (u32)carry;
}

u32 bn_sub(u32 *dst, const u32 *a, const u32 *b, u32 n) {
    u64 borrow = 0;
    for (u32 i = 0; i < n; i++) {
        u64 diff = (u64)a[i] - (u64)b[i] - borrow;
        dst[i] = (u32)diff;
        borrow = (diff >> 63) & 1u;
    }
    return (u32)borrow;
}

u32 bn_mul_small(u32 *dst, const u32 *a, u32 n, u32 factor) {
    u64 carry = 0;
    for (u32 i = 0; i < n; i++) {
        u64 product = (u64)a[i] * (u64)factor + carry;
        dst[i] = (u32)product;
        carry = product >> 32;
    }
    return (u32)carry;
}

u32 bn_div_small(u32 *dst, const u32 *a, u32 n, u32 divisor) {
    if (divisor == 0) {
        return 0xffffffffu;
    }
    u64 remainder = 0;
    for (u32 step = 0; step < n; step++) {
        u32 i = n - 1 - step;
        u64 cur = (remainder << 32) | (u64)a[i];
        dst[i] = (u32)(cur / divisor);
        remainder = cur % divisor;
    }
    return (u32)remainder;
}

void bn_shift_left(u32 *value, u32 n, u32 bits) {
    u32 limbs = bits / 32;
    u32 rest = bits % 32;
    for (u32 step = 0; step < n; step++) {
        u32 i = n - 1 - step;
        u32 low = (i >= limbs) ? value[i - limbs] : 0;
        u32 lower = (i > limbs) ? value[i - limbs - 1] : 0;
        if (rest == 0) {
            value[i] = low;
        } else {
            value[i] = (low << rest) | (lower >> (32 - rest));
        }
    }
}

int bn_compare(const u32 *a, const u32 *b, u32 n) {
    for (u32 step = 0; step < n; step++) {
        u32 i = n - 1 - step;
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

static u32 hex_digit(u32 nibble) {
    return nibble < 10 ? (u32)'0' + nibble : (u32)'a' + (nibble - 10);
}

u32 bn_format_hex(char *out, u32 capacity, const u32 *value, u32 n) {
    u32 written = 0;
    int leading = 1;
    for (u32 step = 0; step < n; step++) {
        u32 i = n - 1 - step;
        for (u32 shift = 32; shift > 0; shift -= 4) {
            u32 nibble = (value[i] >> (shift - 4)) & 0xfu;
            if (leading && nibble == 0 && !(step == n - 1 && shift == 4)) {
                continue;
            }
            leading = 0;
            if (written + 1 >= capacity) {
                return written;
            }
            out[written++] = (char)hex_digit(nibble);
        }
    }
    out[written] = 0;
    return written;
}

const char *bn_status(u32 carry, u32 borrow) {
    if (carry != 0 && borrow != 0) {
        return "bignum overflowed and underflowed in the same round";
    }
    if (carry != 0) {
        return "bignum carry escaped the top limb";
    }
    if (borrow != 0) {
        return "bignum borrow escaped the top limb";
    }
    return "bignum stayed inside its limb budget";
}

u64 corpus_main(u64 seed) {
    u32 a[BN_LIMBS];
    u32 b[BN_LIMBS];
    u32 c[BN_LIMBS];
    char text[80];

    for (u32 i = 0; i < BN_LIMBS; i++) {
        a[i] = (u32)(seed * 2654435761u + i * 40503u);
        b[i] = (u32)(seed * 2246822519u + i * 2654435769u);
        c[i] = 0;
    }

    u32 carry = bn_add(c, a, b, BN_LIMBS);
    u32 borrow = bn_sub(c, c, b, BN_LIMBS);
    carry += bn_mul_small(c, c, BN_LIMBS, 1000003u);
    u32 remainder = bn_div_small(c, c, BN_LIMBS, 65521u);
    bn_shift_left(c, BN_LIMBS, 13);
    int ordering = bn_compare(c, a, BN_LIMBS);
    u32 written = bn_format_hex(text, (u32)sizeof(text), c, BN_LIMBS);
    const char *status = bn_status(carry, borrow);

    u64 total = (u64)written * 31u + (u64)remainder + (u64)(ordering + 2);
    for (u32 i = 0; i < written; i++) {
        total = total * 131u + (u64)(u8)text[i];
    }
    for (const char *p = status; *p != 0; p++) {
        total ^= (u64)(u8)*p;
    }
    return total;
}
