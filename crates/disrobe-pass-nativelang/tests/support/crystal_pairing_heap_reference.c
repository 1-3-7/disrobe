#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct Node Node;
struct Node {
    unsigned char header[16];
    int32_t tag;
    int32_t padding_20;
    int64_t key;
    int32_t tie;
    unsigned char padding_36[12];
    Node *previous;
    Node *next;
    Node *child;
};

_Static_assert(offsetof(Node, tag) == 16, "tag offset");
_Static_assert(offsetof(Node, key) == 24, "key offset");
_Static_assert(offsetof(Node, tie) == 32, "tie offset");
_Static_assert(offsetof(Node, previous) == 48, "previous offset");
_Static_assert(offsetof(Node, next) == 56, "next offset");
_Static_assert(offsetof(Node, child) == 64, "child offset");

extern uint64_t sub_140014e50(uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t sub_1400058c0(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    (void)a; (void)b; (void)c; (void)d;
    abort();
}

uint64_t sub_140005920(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    (void)a; (void)b; (void)c; (void)d;
    abort();
}

static Node *merge(Node *left, Node *right) {
    int left_first = left->key < right->key ||
        (left->key == right->key && left->tie < right->tie);
    Node *winner = left_first ? left : right;
    Node *loser = left_first ? right : left;
    loser->next = winner->child;
    if (winner->child != NULL) {
        winner->child->previous = loser;
    }
    loser->previous = winner;
    winner->child = loser;
    return winner;
}

static Node *combine(Node *list) {
    Node *pending = NULL;
    while (list != NULL) {
        Node *left = list;
        Node *right = left->next;
        list = right == NULL ? NULL : right->next;
        Node *pair = right == NULL ? left : merge(left, right);
        pair->previous = pending;
        pending = pair;
    }
    Node *result = NULL;
    while (pending != NULL) {
        Node *prior = pending->previous;
        result = result == NULL ? pending : merge(result, pending);
        pending = prior;
    }
    if (result != NULL) {
        result->next = NULL;
    }
    return result;
}

static void initialise(Node nodes[10], size_t count, const unsigned order[5],
                       unsigned mode, unsigned children) {
    static const int64_t signed_keys[5] = { INT64_MIN, -1, 0, 1, INT64_MAX };
    for (size_t i = 0; i < count; ++i) {
        nodes[i].tag = 1;
        nodes[i].key = mode == 0 ? (int64_t)order[i] :
            mode == 1 ? signed_keys[order[i]] : 7;
        nodes[i].tie = mode == 2 ? (int32_t)order[i] - 2 : 0;
        nodes[i].previous = i == 0 ? NULL : &nodes[i - 1];
        nodes[i].next = i + 1 == count ? NULL : &nodes[i + 1];
        if (children != 0) {
            nodes[i].child = &nodes[5 + i];
            nodes[5 + i].tag = 1;
            nodes[5 + i].previous = &nodes[i];
        }
    }
}

static int node_index(const Node nodes[10], const Node *node) {
    if (node == NULL) {
        return -1;
    }
    uintptr_t base = (uintptr_t)nodes;
    uintptr_t address = (uintptr_t)node;
    if (address < base || address >= base + 10 * sizeof(Node) ||
        (address - base) % sizeof(Node) != 0) {
        return -2;
    }
    return (int)((address - base) / sizeof(Node));
}

static unsigned cases;

static void grade(size_t count, const unsigned order[5], unsigned mode, unsigned children) {
    Node expected[10] = {0};
    Node observed[10] = {0};
    initialise(expected, count, order, mode, children);
    initialise(observed, count, order, mode, children);
    Node *want = combine(count == 0 ? NULL : expected);
    Node *got = (Node *)(uintptr_t)sub_140014e50(
        count == 0 ? 0 : (uint64_t)(uintptr_t)observed, 0, 0, 0);
    if (node_index(expected, want) != node_index(observed, got)) {
        fprintf(stderr, "root mismatch in case %u\n", cases);
        exit(1);
    }
    for (size_t i = 0; i < 10; ++i) {
        if (expected[i].tag != observed[i].tag || expected[i].key != observed[i].key ||
            expected[i].tie != observed[i].tie ||
            node_index(expected, expected[i].previous) != node_index(observed, observed[i].previous) ||
            node_index(expected, expected[i].next) != node_index(observed, observed[i].next) ||
            node_index(expected, expected[i].child) != node_index(observed, observed[i].child)) {
            fprintf(stderr, "node %zu mismatch in case %u\n", i, cases);
            exit(1);
        }
    }
    ++cases;
}

static void permutations(size_t count, size_t depth, unsigned order[5], unsigned used) {
    if (depth == count) {
        for (unsigned mode = 0; mode < 3; ++mode) {
            for (unsigned children = 0; children < 2; ++children) {
                grade(count, order, mode, children);
            }
        }
        return;
    }
    for (unsigned value = 0; value < count; ++value) {
        if ((used & (1u << value)) == 0) {
            order[depth] = value;
            permutations(count, depth + 1, order, used | (1u << value));
        }
    }
}

int main(void) {
    unsigned order[5] = {0, 1, 2, 3, 4};
    grade(0, order, 0, 0);
    for (size_t count = 1; count <= 5; ++count) {
        permutations(count, 0, order, 0);
        grade(count, order, 3, 0);
        grade(count, order, 3, 1);
    }
    printf("%u\n", cases);
    return 0;
}
