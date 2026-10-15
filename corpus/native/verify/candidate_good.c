unsigned int verify_overflow(unsigned int left, unsigned int right) {
    unsigned int sum = left + right;
    return sum ^ (sum >> 16);
}

unsigned int verify_table(unsigned int index) {
    static const unsigned int values[8] = {
        0x17u, 0x2bu, 0x41u, 0x73u, 0xabu, 0xd1u, 0x101u, 0x167u,
    };
    return values[index & 7u] ^ (index >> 3);
}

unsigned int verify_until_zero(const unsigned char *bytes, unsigned int count) {
    unsigned int position = 0u;
    unsigned int total = 0u;
    while (position < count && bytes[position] != 0u) {
        total += bytes[position];
        position += 1u;
    }
    return total;
}

unsigned int verify_order(int left, unsigned int right) {
    unsigned int result = left < 0 ? 3u : 0u;
    if (right > 0x7fffffffu) {
        result |= 5u;
    }
    if (left < (int)right) {
        result |= 9u;
    }
    return result;
}

unsigned int verify_store(unsigned char *bytes, unsigned int index, unsigned int value) {
    unsigned int slot = index & 63u;
    unsigned int previous = bytes[slot];
    bytes[slot] = (unsigned char)(value + index);
    return previous;
}
