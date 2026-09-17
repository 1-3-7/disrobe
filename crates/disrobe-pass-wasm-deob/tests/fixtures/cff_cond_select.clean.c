__attribute__((export_name("classify_select")))
int classify_select(int n) {
    int acc = n + 1;
    if (n > 10) {
        acc = acc * 3;
    } else {
        acc = acc - 7;
    }
    return acc;
}
