#include <cstdio>
#include <typeinfo>

struct Shape {
    virtual ~Shape() = default;
    virtual int kind() const = 0;
};

struct Circle : Shape {
    int kind() const override { return 1; }
    int radius() const { return 7; }
};

struct Square : Shape {
    int kind() const override { return 2; }
    int side() const { return 5; }
};

int describe(const Shape *s) {
    if (auto *c = dynamic_cast<const Circle *>(s)) {
        return c->radius() + c->kind();
    }
    if (auto *sq = dynamic_cast<const Square *>(s)) {
        return sq->side() + sq->kind();
    }
    return -1;
}

int main() {
    Circle c;
    Square s;
    std::printf("%d %d %s %s\n", describe(&c), describe(&s), typeid(c).name(), typeid(s).name());
    return 0;
}
