struct Pair {
    int first;
    int second;
};

__attribute__((noinline))
int indexed_pair(int index) {
    volatile struct Pair values[4] = {
        {3, 5},
        {7, 11},
        {13, 17},
        {19, 23},
    };
    volatile struct Pair *volatile pair = values;
    int shadow_first = values[index].first;
    int shadow_second = values[index].second;
    int first = pair[index].first;
    int second = pair[index].second;
    return shadow_first + shadow_second + first + second;
}

void _start(void) {
    volatile int value = indexed_pair(1);
    (void)value;
}
