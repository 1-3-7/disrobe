__attribute__((export_name("accumulate")))
int accumulate(int n) {
    int acc = 0;
    for (int i = 0; i < n; i = i + 1) {
        if ((i & 1) == 0) {
            acc = acc + i * 2;
        } else {
            acc = acc + i + 1;
        }
    }
    return acc;
}
