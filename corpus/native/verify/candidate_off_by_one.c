unsigned int verify_overflow(unsigned int left, unsigned int right) {
    unsigned int sum = left + right;
    return (sum ^ (sum >> 16)) + 1u;
}
