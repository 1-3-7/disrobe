#include "corpus.h"

#define VM_STACK_DEPTH 32
#define VM_PROGRAM_MAX 128

enum {
    OP_HALT = 0,
    OP_PUSH = 1,
    OP_POP = 2,
    OP_DUP = 3,
    OP_SWAP = 4,
    OP_ADD = 5,
    OP_SUB = 6,
    OP_MUL = 7,
    OP_DIV = 8,
    OP_AND = 9,
    OP_OR = 10,
    OP_XOR = 11,
    OP_SHL = 12,
    OP_SHR = 13,
    OP_JMP = 14,
    OP_JZ = 15,
    OP_CMP = 16,
    OP_LOAD = 17,
    OP_STORE = 18,
    OP_NEG = 19,
    OP_MOD = 20,
    OP_ROT = 21
};

typedef struct {
    i64 stack[VM_STACK_DEPTH];
    i64 memory[16];
    u32 top;
    u32 pc;
    u32 steps;
    i32 fault;
} VmState;

const char *vm_opcode_name(u32 opcode) {
    switch (opcode) {
        case OP_HALT: return "halt";
        case OP_PUSH: return "push";
        case OP_POP: return "pop";
        case OP_DUP: return "dup";
        case OP_SWAP: return "swap";
        case OP_ADD: return "add";
        case OP_SUB: return "sub";
        case OP_MUL: return "mul";
        case OP_DIV: return "div";
        case OP_AND: return "and";
        case OP_OR: return "or";
        case OP_XOR: return "xor";
        case OP_SHL: return "shl";
        case OP_SHR: return "shr";
        case OP_JMP: return "jmp";
        case OP_JZ: return "jz";
        case OP_CMP: return "cmp";
        case OP_LOAD: return "load";
        case OP_STORE: return "store";
        case OP_NEG: return "neg";
        case OP_MOD: return "mod";
        case OP_ROT: return "rot";
        default: return "unknown opcode outside the dispatch table";
    }
}

static int vm_push(VmState *state, i64 value) {
    if (state->top >= VM_STACK_DEPTH) {
        state->fault = -1;
        return 0;
    }
    state->stack[state->top++] = value;
    return 1;
}

static int vm_pop(VmState *state, i64 *out) {
    if (state->top == 0) {
        state->fault = -2;
        return 0;
    }
    *out = state->stack[--state->top];
    return 1;
}

void vm_reset(VmState *state) {
    for (u32 i = 0; i < VM_STACK_DEPTH; i++) {
        state->stack[i] = 0;
    }
    for (u32 i = 0; i < 16; i++) {
        state->memory[i] = (i64)i * 7 - 3;
    }
    state->top = 0;
    state->pc = 0;
    state->steps = 0;
    state->fault = 0;
}

u32 vm_stack_depth(const VmState *state) {
    return state->top;
}

int vm_verify(const i32 *program, u32 length) {
    u32 position = 0;
    while (position < length) {
        i32 opcode = program[position];
        if (opcode < OP_HALT || opcode > OP_ROT) {
            return 0;
        }
        u32 width = (opcode == OP_PUSH || opcode == OP_JMP || opcode == OP_JZ ||
                     opcode == OP_LOAD || opcode == OP_STORE)
                        ? 2u
                        : 1u;
        if (position + width > length) {
            return 0;
        }
        position += width;
    }
    return 1;
}

i64 vm_run(VmState *state, const i32 *program, u32 length, u32 budget) {
    i64 left = 0;
    i64 right = 0;
    i64 third = 0;
    while (state->pc < length && state->steps < budget && state->fault == 0) {
        i32 opcode = program[state->pc++];
        state->steps++;
        switch (opcode) {
            case OP_HALT:
                return state->top > 0 ? state->stack[state->top - 1] : 0;
            case OP_PUSH:
                if (state->pc >= length) {
                    state->fault = -3;
                    break;
                }
                vm_push(state, (i64)program[state->pc++]);
                break;
            case OP_POP:
                vm_pop(state, &left);
                break;
            case OP_DUP:
                if (vm_pop(state, &left)) {
                    vm_push(state, left);
                    vm_push(state, left);
                }
                break;
            case OP_SWAP:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, left);
                    vm_push(state, right);
                }
                break;
            case OP_ADD:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, right + left);
                }
                break;
            case OP_SUB:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, right - left);
                }
                break;
            case OP_MUL:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, right * left);
                }
                break;
            case OP_DIV:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, left == 0 ? 0 : right / left);
                }
                break;
            case OP_MOD:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, left == 0 ? right : right % left);
                }
                break;
            case OP_ROT:
                if (vm_pop(state, &left) && vm_pop(state, &right) && vm_pop(state, &third)) {
                    vm_push(state, right);
                    vm_push(state, left);
                    vm_push(state, third);
                }
                break;
            case OP_AND:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, right & left);
                }
                break;
            case OP_OR:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, right | left);
                }
                break;
            case OP_XOR:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, right ^ left);
                }
                break;
            case OP_SHL:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, right << (left & 63));
                }
                break;
            case OP_SHR:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, (i64)((u64)right >> (left & 63)));
                }
                break;
            case OP_JMP:
                if (state->pc < length) {
                    state->pc = (u32)program[state->pc] % length;
                } else {
                    state->fault = -4;
                }
                break;
            case OP_JZ:
                if (state->pc < length && vm_pop(state, &left)) {
                    u32 target = (u32)program[state->pc++] % length;
                    if (left == 0) {
                        state->pc = target;
                    }
                } else {
                    state->fault = -5;
                }
                break;
            case OP_CMP:
                if (vm_pop(state, &left) && vm_pop(state, &right)) {
                    vm_push(state, right < left ? -1 : (right > left ? 1 : 0));
                }
                break;
            case OP_LOAD:
                if (state->pc < length) {
                    vm_push(state, state->memory[(u32)program[state->pc++] & 15u]);
                } else {
                    state->fault = -6;
                }
                break;
            case OP_STORE:
                if (state->pc < length && vm_pop(state, &left)) {
                    state->memory[(u32)program[state->pc++] & 15u] = left;
                } else {
                    state->fault = -7;
                }
                break;
            case OP_NEG:
                if (vm_pop(state, &left)) {
                    vm_push(state, -left);
                }
                break;
            default:
                state->fault = -8;
                break;
        }
    }
    return state->top > 0 ? state->stack[state->top - 1] : (i64)state->fault;
}

u32 vm_build_program(i32 *program, u32 capacity, u64 seed) {
    u32 written = 0;
    const i32 body[] = {OP_PUSH, 7,      OP_PUSH, 11,    OP_ADD,  OP_DUP,  OP_MUL,
                        OP_PUSH, 3,      OP_SHL,  OP_PUSH, 5,     OP_XOR,  OP_STORE, 4,
                        OP_LOAD, 4,      OP_PUSH, 2,      OP_MOD, OP_NEG,  OP_PUSH, 0,
                        OP_CMP,  OP_HALT};
    for (u32 i = 0; i < (u32)(sizeof(body) / sizeof(body[0])) && written < capacity; i++) {
        program[written++] = body[i];
    }
    if (written < capacity) {
        program[written++] = (i32)(seed & 1u) ? OP_HALT : OP_POP;
    }
    return written;
}

u64 corpus_main(u64 seed) {
    VmState state;
    i32 program[VM_PROGRAM_MAX];

    vm_reset(&state);
    u32 length = vm_build_program(program, VM_PROGRAM_MAX, seed);
    int valid = vm_verify(program, length);
    i64 result = vm_run(&state, program, length, 8192);
    u32 depth = vm_stack_depth(&state);
    const char *name = vm_opcode_name((u32)(seed % 24u));

    u64 total = (u64)result * 1000003u + (u64)state.steps * 97u + (u64)valid + (u64)depth * 13u;
    for (const char *p = name; *p != 0; p++) {
        total = total * 31u + (u64)(u8)*p;
    }
    return total;
}
