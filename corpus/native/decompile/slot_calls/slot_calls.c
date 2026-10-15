#include <stdint.h>
#include <math.h>
#include <stdlib.h>
#include <windows.h>

int _fltused = 0;

typedef int64_t (*binop_t)(int64_t, int64_t);

__declspec(noinline) int64_t add_op(int64_t a, int64_t b)
{
    return a + b * 3;
}

__declspec(noinline) int64_t xor_op(int64_t a, int64_t b)
{
    return (a ^ b) - 7;
}

binop_t g_op = add_op;
binop_t const g_ops[2] = {add_op, xor_op};

static const char k_alpha[] = "alphabet";
static const char k_beta[] = "alphaBET";

__declspec(noinline) int64_t sum_and_release(int64_t a, int64_t b, void *p)
{
    free(p);
    return a * 3 + b;
}

__declspec(dllexport) int64_t release_twice(int64_t a, int64_t b)
{
    free((void *)0);
    return sum_and_release(a, b, (void *)0) + 1;
}

__declspec(dllexport) int32_t scale_by_import(int32_t a, int32_t b, int32_t c)
{
    return MulDiv(a, b, c) + 1;
}

__declspec(dllexport) int64_t call_through_global(int64_t a, int64_t b)
{
    return g_op(a, b) * 2 + 1;
}

__declspec(dllexport) int64_t call_through_register(int32_t which, int64_t a, int64_t b)
{
    return g_ops[which & 1](a, b) * 5;
}

__declspec(dllexport) int32_t compare_through_import(int32_t which, int32_t length)
{
    int32_t flags = (which & 1) ? NORM_IGNORECASE : 0;
    return CompareStringA(LOCALE_INVARIANT, flags, k_alpha, length & 7, k_beta, (length >> 3) & 7) * 3;
}

__declspec(dllexport) int32_t round_through_import(int64_t a)
{
    return (int32_t)lround((double)a) + 1;
}
