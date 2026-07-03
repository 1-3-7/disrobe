__attribute__((export_name("accumulate")))
int accumulate(int n) {
    int state = 0;
    int i = 0;
    int acc = 0;
    while (1) {
        switch (state) {
            case 0:
                if (i < n) { state = 1; } else { state = 4; }
                break;
            case 1:
                if ((i & 1) == 0) { state = 2; } else { state = 3; }
                break;
            case 2:
                acc = acc + i * 2;
                state = 5;
                break;
            case 3:
                acc = acc + i + 1;
                state = 5;
                break;
            case 5:
                i = i + 1;
                state = 0;
                break;
            default:
                return acc;
        }
    }
}
