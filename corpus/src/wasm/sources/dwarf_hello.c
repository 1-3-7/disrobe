typedef struct {
    int x;
    int y;
} Point;

int add(int a, int b) {
    return a + b;
}

int distance_sq(Point p) {
    return add(p.x * p.x, p.y * p.y);
}

int main(void) {
    Point p = { 3, 4 };
    return distance_sq(p);
}
