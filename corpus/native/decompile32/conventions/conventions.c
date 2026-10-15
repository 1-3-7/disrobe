#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#define STDCALL __stdcall
#define FASTCALL __fastcall
#define NOINLINE __declspec(noinline)
#else
#define STDCALL __attribute__((stdcall))
#define FASTCALL __attribute__((fastcall))
#define THISCALL __attribute__((thiscall))
#define NOINLINE __attribute__((noinline))
#endif

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
#define C_LINKAGE extern "C"
#else
#define C_LINKAGE
#endif

#define API C_LINKAGE EXPORT NOINLINE

#if defined(_MSC_VER)
C_LINKAGE int _fltused;
#endif

struct acc {
    int base;
    int bias;
    int count;
};

API int cd_add3(int a, int b, int c)
{
    return a + b * c;
}

API int cd_clamp(int v, int lo, int hi)
{
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

API unsigned cd_mix(unsigned x, unsigned y)
{
    unsigned rounds = y & 15u;
    for (unsigned i = 0; i < rounds; i++) {
        x = x * 33u ^ (i + y);
    }
    return x;
}

API int cd_many(int a, int b, int c, int d, int e, int f, int g)
{
    return (a - b) * c + (d ^ e) - f * g;
}

API long long cd_add64(long long a, long long b)
{
    return a + b;
}

API long long cd_sub64(long long a, long long b)
{
    return a - b;
}

API long long cd_widen(int a, int b)
{
#if defined(_MSC_VER) && !defined(__clang__)
    return __emul(a, b) + 7;
#else
    return (long long)a * b + 7;
#endif
}

API int cd_chain(int a, int b)
{
    return cd_add3(a, b, 3) + cd_clamp(a, -100, b) * 2;
}

API int cd_keep(int a, int b, int c)
{
    int first = cd_add3(a, b, c);
    int second = cd_add3(b, c, a);
    return first * 3 - second + a;
}

API int STDCALL sc_sub(int a, int b)
{
    return a - b;
}

API int STDCALL sc_select(int a, int b, int c)
{
    return (c & 1) ? a * 5 : b - 9;
}

API int cd_calls_stdcall(int a, int b)
{
    return sc_sub(a, b) * 2 + sc_select(b, a, a);
}

API int FASTCALL fc_lin(int a, int b, int c)
{
    return a * 3 + b - c;
}

API int FASTCALL fc_one(int a)
{
    return a ^ (a >> 3);
}

API int cd_calls_fastcall(int x)
{
    return fc_lin(x, x + 1, x - 2) + fc_one(x) * 3;
}

#ifdef THISCALL
API int THISCALL tc_get(struct acc *self, int k)
{
    return self->base * k + self->bias;
}

API void THISCALL tc_add(struct acc *self, int v)
{
    self->base += v;
    self->count++;
}

API int cd_calls_thiscall(struct acc *s, int v)
{
    tc_add(s, v);
    return tc_get(s, 2) + s->count;
}
#endif

static int table[8] = {3, 1, 4, 1, 5, 9, 2, 6};
int g_counter;

API int g_table_pick(int i)
{
    return table[i & 7] * 10 + i;
}

API int g_bump(int by)
{
    g_counter += by;
    return g_counter ^ 5;
}

API double fp_half(int a)
{
    return a * 0.5;
}

API float fp_scale(float x, float y)
{
    return x * 2.0f + y;
}
