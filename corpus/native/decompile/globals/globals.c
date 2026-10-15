#include <stdint.h>

int64_t g_counter = 5;
int32_t g_table[8] = {3, 1, 4, 1, 5, 9, 2, 6};
static int32_t s_mode = 7;
static volatile uint8_t s_flags = 0x5a;
uint8_t g_bits = 0x2c;
uint8_t g_bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};

__declspec(dllexport) int64_t bump(int64_t by)
{
    g_counter += by;
    return g_counter * 3;
}

__declspec(dllexport) int32_t table_pick(int32_t i)
{
    return g_table[i & 7] * s_mode;
}

__declspec(dllexport) void set_mode(int32_t m)
{
    s_mode = m ^ 3;
}

__declspec(dllexport) int32_t mode_flags(int32_t x)
{
    return (s_mode & 1) ? x + s_mode : x - 1;
}

__declspec(dllexport) int64_t clamp_counter(int64_t a)
{
    if (g_counter > a) {
        g_counter = a;
    }
    return g_counter + 1;
}

__declspec(dllexport) int32_t toggle_flags(int32_t bit)
{
    s_flags = (uint8_t)(s_flags + bit * 3);
    return s_flags ^ 0x11;
}

__declspec(dllexport) int32_t flag_bit(int32_t x)
{
    return (s_flags & 4) ? x * 2 : x + 9;
}

__declspec(dllexport) int64_t masked_counter(int64_t mask)
{
    return (g_counter & mask) ? g_counter - mask : mask + 17;
}

__declspec(dllexport) int32_t bits_test(int32_t x)
{
    if (g_bits & 4) {
        g_bits = (uint8_t)(g_bits + x);
        return x * 7;
    }
    return x - 3;
}

__declspec(dllexport) int32_t bits_select(int32_t x)
{
    return (g_bits & 0x10) ? x : -x;
}

__declspec(dllexport) int32_t byte_table_test(int32_t i)
{
    return (g_bytes[i & 7] & 2) ? i + 100 : i - 100;
}
