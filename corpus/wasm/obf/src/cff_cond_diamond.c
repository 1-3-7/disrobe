__attribute__((export_name("classify")))
int classify(int n) {
    int state = 0;
    int acc = 0;
    while (1) {
        switch (state) {
            case 0:
                acc = n + 1;
                if (n > 10) { state = 1; } else { state = 2; }
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
