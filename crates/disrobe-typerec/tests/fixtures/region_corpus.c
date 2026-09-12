int g_counter = 3;
int g_zero;
const int g_const_table[4] = {11, 22, 33, 44};
__thread int t_slot = 7;
__thread int t_zero;

int bump(int n) {
    g_counter += n;
    g_zero = g_counter;
    t_slot += n;
    t_zero = t_slot;
    return g_counter + g_const_table[n & 3] + t_slot + t_zero;
}

int reload(int n) {
    int local = g_counter;
    g_zero = local + n;
    return local + g_zero;
}

void _start(void) {
    bump(1);
    reload(2);
}
