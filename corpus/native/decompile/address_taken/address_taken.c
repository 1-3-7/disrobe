#include <stdarg.h>
#include <stdint.h>

struct pair {
    int64_t first;
    int64_t second;
};

__declspec(noinline) void split_halves(int64_t value, int32_t *low, int32_t *high)
{
    *low = (int32_t)value;
    *high = (int32_t)(value >> 32);
}

__declspec(noinline) void fill_pair(struct pair *out, int64_t value)
{
    out->first = value * 3;
    out->second = value ^ 0x55;
}

__declspec(noinline) void fill_quad(int32_t *out, int32_t value)
{
    out[0] = value + 1;
    out[1] = value * 2;
    out[2] = value - 9;
    out[3] = value ^ 0x1234;
}

__declspec(noinline) int32_t first_nonzero(const uint8_t *bytes, int32_t count)
{
    for (int32_t i = 0; i < count; i++) {
        if (bytes[i] != 0) {
            return i;
        }
    }
    return -1;
}

__declspec(noinline) int64_t sum_va(int32_t count, ...)
{
    va_list arguments;
    int64_t total = 0;
    va_start(arguments, count);
    for (int32_t i = 0; i < count; i++) {
        total += va_arg(arguments, int64_t) * (i + 1);
    }
    va_end(arguments);
    return total;
}

__declspec(dllexport) int64_t call_va(int64_t a, int64_t b)
{
    return sum_va(5, a, b, a + b, a - b, a ^ b) + 1;
}

__declspec(dllexport) int64_t through_out_params(int64_t value)
{
    int32_t low;
    int32_t high;
    split_halves(value, &low, &high);
    return (int64_t)low * 3 - high;
}

__declspec(dllexport) int64_t through_struct(int64_t value)
{
    struct pair p;
    fill_pair(&p, value);
    return p.first - p.second;
}

__declspec(dllexport) int32_t through_array(int32_t value)
{
    int32_t quad[4];
    fill_quad(quad, value);
    return quad[0] + quad[1] * 2 + quad[2] * 3 + quad[3] * 4;
}

#pragma strict_gs_check(push, on)
__declspec(dllexport) int32_t guarded_scan(int32_t seed, int32_t where)
{
    uint8_t bytes[16];
    for (int32_t i = 0; i < 16; i++) {
        bytes[i] = 0;
    }
    if (where & 1) {
        bytes[3] = (uint8_t)(seed | 1);
    } else {
        bytes[11] = (uint8_t)(seed | 1);
    }
    if (seed < 0) {
        return first_nonzero(bytes, 16) - 100;
    }
    return first_nonzero(bytes, 16) + 100;
}
#pragma strict_gs_check(pop)
