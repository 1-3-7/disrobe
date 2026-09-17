__attribute__((visibility("hidden"))) int hidden_helper(int x) {
    return x * 17 + 3;
}

__attribute__((visibility("default"))) int public_entry(int x) {
    return hidden_helper(x) ^ 0x5A;
}

int main(int argc, char **argv) {
    (void)argv;
    return public_entry(argc) & 0xff;
}
