#include "corpus.h"

int main(int argc, char **argv) {
    (void)argv;
    u64 result = corpus_main((u64)argc);
    return (int)((result ^ (result >> 32)) & 0x7f);
}
