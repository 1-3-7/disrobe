__declspec(dllimport) void __stdcall ExitProcess(unsigned int code);

typedef int (*op_fn)(int);

static int twice(int x) {
    return x * 2;
}

static int thrice(int x) {
    return x * 3;
}

volatile op_fn table[2] = {twice, thrice};

int work(int n) {
    volatile char buf[64];
    for (int i = 0; i < n; i++) {
        buf[i & 63] = (char)i;
    }
    return buf[n & 63] + table[n & 1](n);
}

void __stdcall entry(void) {
    ExitProcess((unsigned int)work(7));
}
