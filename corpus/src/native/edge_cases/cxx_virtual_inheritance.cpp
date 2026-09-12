#include <cstdio>

struct Animal {
    int legs = 0;
    virtual int sound() const = 0;
    virtual ~Animal() = default;
};

struct Mammal : virtual Animal {
    Mammal() { legs = 4; }
    int sound() const override { return 1; }
};

struct Swimmer : virtual Animal {
    Swimmer() {}
    int sound() const override { return 2; }
};

struct Whale : Mammal, Swimmer {
    int sound() const override { return Mammal::sound() + Swimmer::sound() + legs; }
};

int main() {
    Whale w;
    std::printf("%d\n", w.sound());
    return 0;
}
