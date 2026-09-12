#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((section("__TEXT,__edge_many")))
static const char segment_pressure[64] = "disrobe Mach-O segment-count edge marker";

__attribute__((used, section("__DATA,__objc_imageinfo")))
static const uint32_t objc_image_info[2] = {0u, 0x40u};

__attribute__((constructor))
static void on_load(void) {
    volatile uint64_t mix = 0xcafebabedeadbeefull;
    mix ^= (uint64_t)(uintptr_t)segment_pressure;
    (void)mix;
}

__attribute__((destructor))
static void on_unload(void) {
    volatile uint32_t flag = objc_image_info[1];
    (void)flag;
}

__attribute__((noinline))
int edge_fold(int a, int b) {
    int acc = a;
    for (int i = 0; i < b; ++i) {
        acc = (acc << 1) ^ (acc >> 3) ^ (i & 0x7f);
    }
    return acc;
}

__attribute__((visibility("hidden")))
int edge_hidden(int seed) {
    return edge_fold(seed, (seed & 0x1f) + 1);
}

extern int edge_external(int seed);

int edge_external(int seed) {
    int total = 0;
    const char *p = segment_pressure;
    while (*p) {
        total += (int)(unsigned char)*p++;
    }
    return edge_hidden(seed) ^ total;
}

int main(int argc, char **argv) {
    int seed = argc;
    for (int i = 1; i < argc; ++i) {
        seed ^= (int)strlen(argv[i]);
    }
    int out = edge_external(seed);
    printf("edge=%d info=%u\n", out, objc_image_info[1]);
    return out & 0x7f;
}
