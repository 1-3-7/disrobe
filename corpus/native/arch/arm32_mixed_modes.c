__attribute__((target("thumb"))) int thumb_scale(int value, int factor) {
    int total = value * factor;
    if (total > 100) {
        total = total - 100;
    }
    return total + 7;
}

__attribute__((target("arm"))) int arm_add(int a, int b) {
    return a + b * 5;
}

__attribute__((target("arm"))) int arm_pick(int a, int b) {
    if (a > b) {
        return a - b;
    }
    return b - a;
}

__attribute__((target("arm"))) void _start(void) {
    volatile int r = arm_add(3, 4);
    r = arm_pick(r, 9);
    r = thumb_scale(r, 3);
    (void)r;
}
