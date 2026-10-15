#include <stdint.h>

__declspec(noinline) int64_t step3(int64_t a, int64_t b, int64_t c)
{
    return (a ^ (b << 3)) + c * 5;
}

__declspec(noinline) int32_t mix7(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e, int32_t f, int32_t g)
{
    return a - b + c * d - e + (f ^ g) * 3;
}

__declspec(dllexport) int32_t pass_seven_twice(int32_t x, int32_t y, int32_t z)
{
    int32_t first = mix7(x, y, z, x + 1, y + 2, z + 3, 0);
    return first + mix7(z, y, x, 1, 2, 3, -1);
}

__declspec(dllexport) int64_t keep_across_calls(int64_t a, int64_t b, int64_t c, int64_t d)
{
    int64_t p = step3(a, b, c);
    int64_t q = step3(b, c, d);
    int64_t r = step3(c, d, a);
    int64_t s = step3(d, a, b);
    return p * 3 + q * 5 + r * 7 + s * 11 + a - d;
}

__declspec(dllexport) int64_t wide_leaf(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f)
{
    int64_t t0 = a * b + c;
    int64_t t1 = b * c + d;
    int64_t t2 = c * d + e;
    int64_t t3 = d * e + f;
    int64_t t4 = e * f + a;
    int64_t t5 = f * a + b;
    int64_t t6 = t0 ^ t3;
    int64_t t7 = t1 ^ t4;
    int64_t t8 = t2 ^ t5;
    return (t0 + t1 * 3) ^ (t2 - t3) ^ (t4 + t5 * 7) ^ (t6 * t7 - t8);
}

__declspec(dllexport) int64_t chain_calls(int64_t a, int64_t b)
{
    int64_t acc = 0;
    for (int i = 0; i < 4; i++) {
        acc += step3(a + i, b - i, acc);
    }
    return acc;
}

__declspec(dllexport) int64_t call_wide_leaf(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f)
{
    return wide_leaf(a, b, c, d, e, f) + 1;
}

__declspec(dllexport) int64_t stack_args_across_call(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f)
{
    int64_t t = step3(a, b, c);
    return t * e + d - f;
}

__declspec(dllexport) int64_t spill_across_calls(int64_t a, int64_t b, int64_t c, int64_t d)
{
    int64_t v0 = a * 3, v1 = b * 5, v2 = c * 7, v3 = d * 11, v4 = a ^ b, v5 = c ^ d;
    int64_t v6 = a + d, v7 = b + c, v8 = a - c, v9 = b - d;
    int64_t r = step3(v0, v1, v2);
    r += step3(v3, v4, v5);
    return r + v0 * v1 + v2 * v3 + v4 * v5 + v6 * v7 + v8 * v9 + v6 - v9;
}
