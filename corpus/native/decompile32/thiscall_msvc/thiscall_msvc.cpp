struct __declspec(dllexport) acc {
    int base;
    int bias;
    int count;
    __declspec(noinline) int get(int k);
    __declspec(noinline) void add(int v);
    __declspec(noinline) int add_then_get(int v);
    __declspec(noinline) int mix(int a, int b, int c);
};

int acc::get(int k)
{
    return base * k + bias;
}

void acc::add(int v)
{
    base += v;
    count++;
}

int acc::add_then_get(int v)
{
    add(v);
    return get(2) + count;
}

int acc::mix(int a, int b, int c)
{
    return (a - base) * b + (c ^ bias) - count;
}
