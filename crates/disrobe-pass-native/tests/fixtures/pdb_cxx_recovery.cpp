enum class ColorTag : unsigned char {
    Red = 1,
    Green = 2,
    Blue = 4,
};

enum Priority : short {
    PriorityLow = -1,
    PriorityNormal = 0,
    PriorityHigh = 1,
};

struct Vector3 {
    float x;
    float y;
    float z;
};

union Payload {
    int as_int;
    float as_float;
    unsigned char bytes[4];
};

struct Flags {
    unsigned int active : 1;
    unsigned int visible : 1;
    unsigned int priority : 6;
    unsigned int reserved : 24;
};

struct Node {
    int value;
    const Vector3 *position;
    Node *next;
    ColorTag tag;
    Priority pri;
    Flags flags;
    int matrix[2][3];
    Payload data;
    char label[16];
};

struct Base {
    int base_a;
    int base_b;
};

struct Derived : Base {
    int derived_c;
    Vector3 offset;
};

struct LeftMix {
    int left_x;
};

struct RightMix {
    int right_y;
    int right_z;
};

struct Multi : LeftMix, RightMix {
    int multi_w;
};

struct Shape {
    virtual int area() const { return shape_tag; }
    int shape_tag;
    Priority shape_pri;
};

typedef Node *NodePtr;

Node g_root;
int g_counter;
Derived g_derived;
Multi g_multi;

int compute_sum(const Node *n, int extra);
NodePtr find_next(Node *n);
int touch_shape(const Shape *s);

int compute_sum(const Node *n, int extra) {
    return n->value + extra;
}

NodePtr find_next(Node *n) {
    return n->next;
}

int touch_shape(const Shape *s) {
    return s->shape_tag + static_cast<int>(s->shape_pri);
}

extern "C" void EntryPoint() {
    g_root.value = 0;
    g_root.next = 0;
    g_counter = compute_sum(&g_root, 1);
    g_derived.derived_c = 0;
    g_multi.multi_w = 0;
}
