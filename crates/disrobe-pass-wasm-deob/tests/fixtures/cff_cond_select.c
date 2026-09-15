__attribute__((export_name("classify_select")))
int classify_select(int n) {
    int state = 0;
    int acc = 0;
    while (1) {
        switch (state) {
            case 0:
                acc = n + 1;
                state = n > 10 ? 1 : 2;
                break;
            case 1:
                acc = acc * 3;
                state = 3;
                break;
            case 2:
                acc = acc - 7;
                state = 3;
                break;
            default:
                return acc;
        }
    }
}
