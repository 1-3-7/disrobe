__declspec(noinline) int first_probe(int value) {
    volatile int slots[8];
    slots[0] = value;
    return slots[0] + 1;
}

__declspec(noinline) int second_probe(int value) {
    volatile int slots[16];
    slots[0] = value;
    return slots[0] * 3;
}

__declspec(noinline) int pdata_only_probe(int value) {
    volatile int slots[24];
    slots[0] = value;
    return slots[0] - 5;
}

int main_probe(void) {
    return first_probe(7) + second_probe(11);
}
