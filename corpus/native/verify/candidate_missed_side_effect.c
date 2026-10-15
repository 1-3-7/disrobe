unsigned int verify_store(unsigned char *bytes, unsigned int index, unsigned int value) {
    unsigned int slot = index & 63u;
    unsigned int previous = bytes[slot];
    return previous + (value & 0u);
}
