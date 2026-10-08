#include "common.h"

static uint32_t mix(uint32_t seed, int rounds) {
    uint32_t value = seed;
    for (int i = 0; i < rounds; i++) {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
    }
    return value;
}

int main(void) {
    DWORD started = GetTickCount();
    uint32_t value = mix(0x12345678u, 8);
    char path[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, path, MAX_PATH);
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    printf("check=clean_control mix=%#x path_len=%lu elapsed_ok=%d\n", (unsigned)value,
           (unsigned long)length, started <= GetTickCount());
    report("clean_control", 0);
    return counter.QuadPart == 0 ? 1 : 0;
}
