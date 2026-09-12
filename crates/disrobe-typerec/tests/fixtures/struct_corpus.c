struct Point {
    int x;
    int y;
};

struct Mixed {
    signed char c;
    int n;
    long long q;
    unsigned short w;
};

struct Node {
    long long val;
    struct Node *next;
};

struct Flags {
    unsigned int mask;
    unsigned char lo;
};

union U {
    int i;
    long long q;
};

struct Inner {
    int a;
    int b;
};

struct Outer {
    struct Inner in;
    long long tag;
};

int sum_point(struct Point *p) {
    return p->x + p->y;
}

long long mixed_read(struct Mixed *m) {
    return (long long)m->c + m->n + m->q + m->w;
}

long long list_last(struct Node *n) {
    while (n->next) {
        n = n->next;
    }
    return n->val;
}

unsigned int flags_read(struct Flags *f) {
    return f->mask + f->lo;
}

int arr_sum(int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += a[i];
    }
    return s;
}

long long union_read(union U *u) {
    return u->q + u->i;
}

long long outer_read(struct Outer *o) {
    return (long long)o->in.a + o->in.b + o->tag;
}

void _start(void) {
    struct Point pt = {3, 4};
    struct Mixed mx = {1, 2, 3, 4};
    struct Node n1 = {7, 0};
    struct Node n0 = {5, &n1};
    struct Flags fl = {0xff00, 2};
    union U un;
    un.q = 9;
    int arr[4] = {1, 2, 3, 4};
    struct Outer ou = {{5, 6}, 7};

    volatile int a = sum_point(&pt);
    volatile long long b = mixed_read(&mx);
    volatile long long c = list_last(&n0);
    volatile unsigned int d = flags_read(&fl);
    volatile int e = arr_sum(arr, 4);
    volatile long long g = union_read(&un);
    volatile long long h = outer_read(&ou);
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)g;
    (void)h;
}
