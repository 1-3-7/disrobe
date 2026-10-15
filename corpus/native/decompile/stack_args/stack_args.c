#include <stdint.h>
#include <intrin.h>

__declspec(noinline) int64_t mix6(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f)
{
    return a * 3 + b - c * 5 + (d ^ e) - f * 7;
}

__declspec(noinline) int32_t mix7(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e, int32_t f, int32_t g)
{
    return a - b + c * d - e + (f ^ g) * 3;
}

__declspec(noinline) int64_t opaque_mix6(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f)
{
    int64_t bits = e ^ (f << 7);
    return (a - b) * 11 + c * d - (_bittest64(&bits, f & 63) ? 5 : 9);
}

__declspec(noinline) int64_t pick5(int64_t a, int64_t b, int64_t c, int64_t d, const int64_t *e)
{
    return e == 0 ? a - b + c - d : *e;
}

__declspec(dllexport) int64_t pass_six(int64_t x, int64_t y)
{
    return mix6(x, y, x + y, x - y, x * y, y * 7 + 1) + 1;
}

__declspec(dllexport) int64_t pass_unresolved(int64_t x, int64_t y)
{
    return opaque_mix6(y, x, y - x, 9, x ^ y, -x) - 2;
}

__declspec(dllexport) int64_t pass_null(int64_t x, int64_t y)
{
    return pick5(x, y, x | y, x & y, 0) * 3;
}

__declspec(dllexport) int32_t pass_five_int(int32_t a, int32_t b)
{
    return mix7(a, b, a + b, a - b, a * b, b >> 2, a << 3) ^ 3;
}

__declspec(dllexport) int64_t call_mix6(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f)
{
    return mix6(a, b, c, d, e, f);
}

__declspec(dllexport) int32_t call_mix7(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e, int32_t f, int32_t g)
{
    return mix7(a, b, c, d, e, f, g);
}
