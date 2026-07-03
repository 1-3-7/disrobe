#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#define DR_EXPORT __declspec(dllexport)
#else
#define DR_EXPORT __attribute__((visibility("default"), used))
#endif

typedef struct VmCtx {
    int64_t *regs;
    int64_t *stack;
    int32_t *sp;
    uint32_t *pc;
    int64_t *scratch;
    uint8_t *prog;
} VmCtx;

static int32_t rd_i32(const uint8_t *p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

void h_push_imm(VmCtx *c) {
    int64_t v = (int64_t)rd_i32(c->prog + *c->pc);
    c->stack[*c->sp] = v;
    *c->sp += 1;
    *c->pc += 4;
}

void h_push_reg(VmCtx *c) {
    uint8_t idx = c->prog[*c->pc];
    c->stack[*c->sp] = c->regs[idx];
    *c->sp += 1;
    *c->pc += 1;
}

void h_pop_reg(VmCtx *c) {
    uint8_t idx = c->prog[*c->pc];
    *c->sp -= 1;
    c->regs[idx] = c->stack[*c->sp];
    *c->pc += 1;
}

void h_add(VmCtx *c) {
    uint64_t b = (uint64_t)c->stack[*c->sp - 1];
    uint64_t a = (uint64_t)c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = (int64_t)(a + b);
}

void h_sub(VmCtx *c) {
    uint64_t b = (uint64_t)c->stack[*c->sp - 1];
    uint64_t a = (uint64_t)c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = (int64_t)(a - b);
}

void h_mul(VmCtx *c) {
    uint64_t b = (uint64_t)c->stack[*c->sp - 1];
    uint64_t a = (uint64_t)c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = (int64_t)(a * b);
}

void h_xor(VmCtx *c) {
    int64_t b = c->stack[*c->sp - 1];
    int64_t a = c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = a ^ b;
}

void h_and(VmCtx *c) {
    int64_t b = c->stack[*c->sp - 1];
    int64_t a = c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = a & b;
}

void h_or(VmCtx *c) {
    int64_t b = c->stack[*c->sp - 1];
    int64_t a = c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = a | b;
}

void h_shl(VmCtx *c) {
    uint64_t b = (uint64_t)c->stack[*c->sp - 1];
    uint64_t a = (uint64_t)c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = (int64_t)(a << (b & 63));
}

void h_cmp_lt(VmCtx *c) {
    int64_t b = c->stack[*c->sp - 1];
    int64_t a = c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = (a < b) ? 1 : 0;
}

void h_cmp_eq(VmCtx *c) {
    int64_t b = c->stack[*c->sp - 1];
    int64_t a = c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = (a == b) ? 1 : 0;
}

void h_cmp_gt(VmCtx *c) {
    int64_t b = c->stack[*c->sp - 1];
    int64_t a = c->stack[*c->sp - 2];
    *c->sp -= 1;
    c->stack[*c->sp - 1] = (a > b) ? 1 : 0;
}

void h_neg(VmCtx *c) {
    uint64_t v = (uint64_t)c->stack[*c->sp - 1];
    c->stack[*c->sp - 1] = (int64_t)(0ull - v);
}

void h_br_true(VmCtx *c) {
    uint32_t target = rd_u32(c->prog + *c->pc);
    *c->sp -= 1;
    int64_t cond = c->stack[*c->sp];
    if (cond != 0) {
        *c->pc = target;
    } else {
        *c->pc += 4;
    }
}

void h_br_false(VmCtx *c) {
    uint32_t target = rd_u32(c->prog + *c->pc);
    *c->sp -= 1;
    int64_t cond = c->stack[*c->sp];
    if (cond == 0) {
        *c->pc = target;
    } else {
        *c->pc += 4;
    }
}

void h_jump(VmCtx *c) {
    uint32_t target = rd_u32(c->prog + *c->pc);
    *c->pc = target;
}

void h_ret(VmCtx *c) { *c->pc = 0xFFFFFFFFu; }

typedef void (*VmHandler)(VmCtx *);

DR_EXPORT VmHandler dr_vm_handlers[] = {
    h_push_imm, h_push_reg, h_pop_reg, h_add,     h_sub,
    h_mul,      h_xor,      h_and,     h_or,      h_shl,
    h_cmp_lt,   h_cmp_eq,   h_cmp_gt,  h_neg,     h_br_true,
    h_br_false, h_jump,     h_ret,
};

DR_EXPORT uint32_t dr_vm_handler_count = 18;

enum {
    OP_PUSH_IMM = 0,
    OP_PUSH_REG = 1,
    OP_POP_REG = 2,
    OP_ADD = 3,
    OP_SUB = 4,
    OP_MUL = 5,
    OP_XOR = 6,
    OP_AND = 7,
    OP_OR = 8,
    OP_SHL = 9,
    OP_CMP_LT = 10,
    OP_CMP_EQ = 11,
    OP_CMP_GT = 12,
    OP_NEG = 13,
    OP_BR_TRUE = 14,
    OP_BR_FALSE = 15,
    OP_JUMP = 16,
    OP_RET = 17,
};

DR_EXPORT uint8_t dr_vm_prog[] = {
#include "vm_oracle_bytecode.inc"
};

DR_EXPORT uint32_t dr_vm_prog_len = sizeof(dr_vm_prog);

DR_EXPORT uint32_t dr_vm_entry = 0;

DR_EXPORT int64_t dr_vm_dispatch(int64_t a0, int64_t a1, int64_t a2) {
    int64_t regs[256];
    int64_t stack[4096];
    int64_t scratch[256];
    int32_t sp = 0;
    uint32_t pc = dr_vm_entry;
    for (int i = 0; i < 256; i++) {
        regs[i] = 0;
    }
    regs[0] = a0;
    regs[1] = a1;
    regs[2] = a2;
    VmCtx ctx;
    ctx.regs = regs;
    ctx.stack = stack;
    ctx.sp = &sp;
    ctx.pc = &pc;
    ctx.scratch = scratch;
    ctx.prog = dr_vm_prog;
    uint32_t guard = 0;
    while (pc != 0xFFFFFFFFu) {
        if (guard++ > 50000000u) {
            break;
        }
        uint8_t op = dr_vm_prog[pc];
        pc += 1;
        dr_vm_handlers[op](&ctx);
    }
    if (sp > 0) {
        return stack[sp - 1];
    }
    return regs[0];
}

int main(int argc, char **argv) {
    int64_t a = argc > 1 ? atoll(argv[1]) : 0;
    int64_t b = argc > 2 ? atoll(argv[2]) : 0;
    int64_t cc = argc > 3 ? atoll(argv[3]) : 0;
    int64_t r = dr_vm_dispatch(a, b, cc);
    printf("%lld\n", (long long)r);
    return 0;
}
