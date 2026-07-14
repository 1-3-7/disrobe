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

typedef Node *NodePtr;

Node g_root;
int g_counter;

int compute_sum(const Node *n, int extra);
NodePtr find_next(Node *n);

int compute_sum(const Node *n, int extra) {
    return n->value + extra;
}

NodePtr find_next(Node *n) {
    return n->next;
}

extern "C" void EntryPoint() {
    g_root.value = 0;
    g_root.next = 0;
    g_counter = compute_sum(&g_root, 1);
}
