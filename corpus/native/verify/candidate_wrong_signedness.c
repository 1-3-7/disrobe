unsigned int verify_order(int left, unsigned int right) {
    unsigned int result = (unsigned int)left < right ? 3u : 0u;
    if (right > 0x7fffffffu) {
        result |= 5u;
    }
    if ((unsigned int)left < right) {
        result |= 9u;
    }
    return result;
}
