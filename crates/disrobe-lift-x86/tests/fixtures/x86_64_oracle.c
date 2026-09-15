#include <stddef.h>
#include <stdint.h>

__attribute__((noinline)) uint64_t add_pair(uint64_t left, uint64_t right) {
    return left + right;
}

__attribute__((noinline)) uint64_t mix_pair(uint64_t left, uint64_t right) {
    return ((left * 3U) + right) ^ UINT64_C(0x55aa);
}

__attribute__((noinline)) int branch_zero(int value) {
    if (value == 0) {
        return 7;
    }
    return value - 1;
}

__attribute__((noinline)) uint64_t memory_add(uint64_t *pointer, uint64_t value) {
    uint64_t previous = *pointer;
    *pointer = previous + value;
    return previous;
}

__attribute__((noinline)) uint64_t multiply_pair(uint64_t left, uint64_t right) {
    return (left * right) + left;
}

__attribute__((noinline)) uint64_t bit_pair(uint64_t left, uint64_t right) {
    return (left & right) | (left ^ UINT64_C(0x1234));
}

__attribute__((noinline)) uint64_t shift_pair(uint64_t value) {
    return (value << 5U) ^ (value >> 3U);
}

__attribute__((noinline)) int64_t signed_shift(int64_t value) {
    return value >> 7U;
}

__attribute__((noinline)) uint64_t divide_pair(uint64_t dividend, uint64_t divisor) {
    return dividend / (divisor | UINT64_C(1));
}

__attribute__((noinline)) int64_t signed_divide_pair(int64_t dividend, int64_t divisor) {
    return dividend / (divisor | INT64_C(1));
}

__attribute__((noinline)) uint64_t extend_bytes(const uint8_t *left, const int8_t *right) {
    return (uint64_t)*left + (uint64_t)(int64_t)*right;
}

__attribute__((noinline)) uint64_t indexed_load(const uint64_t *pointer, size_t index) {
    return pointer[index + 3U];
}

__attribute__((noinline)) uint64_t call_pair(uint64_t left, uint64_t right) {
    return add_pair(left, right) + UINT64_C(1);
}

__attribute__((used, noinline, noclone)) void condition_forms(void) {
    __asm__(
        ".intel_syntax noprefix\n\t"
        "seto al\n\t"
        "setno al\n\t"
        "setb al\n\t"
        "setae al\n\t"
        "sete al\n\t"
        "setne al\n\t"
        "setbe al\n\t"
        "seta al\n\t"
        "sets al\n\t"
        "setns al\n\t"
        "setp al\n\t"
        "setnp al\n\t"
        "setl al\n\t"
        "setge al\n\t"
        "setle al\n\t"
        "setg al\n\t"
        "setne byte ptr [rdi]\n\t"
        "cmovo rax, rbx\n\t"
        "cmovno rax, rbx\n\t"
        "cmovb rax, rbx\n\t"
        "cmovae rax, rbx\n\t"
        "cmove rax, rbx\n\t"
        "cmovne rax, rbx\n\t"
        "cmovbe rax, rbx\n\t"
        "cmova rax, rbx\n\t"
        "cmovs rax, rbx\n\t"
        "cmovns rax, rbx\n\t"
        "cmovp rax, rbx\n\t"
        "cmovnp rax, rbx\n\t"
        "cmovl rax, rbx\n\t"
        "cmovge rax, rbx\n\t"
        "cmovle rax, rbx\n\t"
        "cmovg rax, rbx\n\t"
        "cmovne rax, qword ptr [rdi]\n\t"
        ".att_syntax prefix\n\t");
}

__attribute__((used, noinline, noclone)) void extended_integer_forms(void) {
    __asm__(
        ".intel_syntax noprefix\n\t"
        "bt rax, rbx\n\t"
        "bts rax, rcx\n\t"
        "btr rax, rdx\n\t"
        "btc rax, rsi\n\t"
        "bt rax, 9\n\t"
        "bt qword ptr [rdi], rax\n\t"
        "bts qword ptr [rdi], rcx\n\t"
        "btr qword ptr [rdi], rdx\n\t"
        "btc qword ptr [rdi], rsi\n\t"
        "bt qword ptr [rdi], 9\n\t"
        "bsf rax, rbx\n\t"
        "bsr rax, rbx\n\t"
        "popcnt rax, rbx\n\t"
        "tzcnt rax, rbx\n\t"
        "lzcnt rax, rbx\n\t"
        "bsf rax, qword ptr [rdi]\n\t"
        "bsr rax, qword ptr [rdi]\n\t"
        "popcnt rax, qword ptr [rdi]\n\t"
        "tzcnt rax, qword ptr [rdi]\n\t"
        "lzcnt rax, qword ptr [rdi]\n\t"
        "bswap rax\n\t"
        "bswap ecx\n\t"
        "xadd rax, rbx\n\t"
        "xadd qword ptr [rdi], rbx\n\t"
        "imul rax, rbx\n\t"
        "imul rax, qword ptr [rdi]\n\t"
        "imul rcx, rdx, 7\n\t"
        "imul rcx, qword ptr [rdi], 7\n\t"
        "movsxd rax, ecx\n\t"
        "movsxd rax, dword ptr [rdi]\n\t"
        "cbw\n\t"
        "cwde\n\t"
        "cdqe\n\t"
        "cwd\n\t"
        "cdq\n\t"
        "cqo\n\t"
        "shld rax, rbx, 5\n\t"
        "shrd rax, rbx, 7\n\t"
        "shld qword ptr [rdi], rbx, 5\n\t"
        "shrd qword ptr [rdi], rbx, 7\n\t"
        "shld rax, rbx, cl\n\t"
        "shrd rax, rbx, cl\n\t"
        "shl rax, cl\n\t"
        "shr rbx, cl\n\t"
        "sar rdx, cl\n\t"
        "shl qword ptr [rdi], cl\n\t"
        "shr qword ptr [rdi], cl\n\t"
        "sar qword ptr [rdi], cl\n\t"
        "shld qword ptr [rdi], rbx, cl\n\t"
        "shrd qword ptr [rdi], rbx, cl\n\t"
        ".att_syntax prefix\n\t");
}

__attribute__((used, noinline, noclone)) void scalar_vector_forms(void) {
    __asm__(
        ".intel_syntax noprefix\n\t"
        "movss xmm0, xmm1\n\t"
        "movss xmm0, dword ptr [rax]\n\t"
        "movss dword ptr [rax], xmm0\n\t"
        "movsd xmm1, xmm2\n\t"
        "movsd xmm1, qword ptr [rax]\n\t"
        "movsd qword ptr [rax], xmm1\n\t"
        "movaps xmm2, xmm3\n\t"
        "movaps xmm2, xmmword ptr [rax]\n\t"
        "movaps xmmword ptr [rax], xmm2\n\t"
        "movups xmm4, xmm5\n\t"
        "movups xmm4, xmmword ptr [rax]\n\t"
        "movups xmmword ptr [rax], xmm4\n\t"
        "movd xmm0, eax\n\t"
        "movd eax, xmm0\n\t"
        "movq xmm0, rax\n\t"
        "movq rax, xmm0\n\t"
        "pxor xmm0, xmm1\n\t"
        "xorps xmm2, xmm3\n\t"
        "xorpd xmm4, xmm5\n\t"
        "andps xmm6, xmm7\n\t"
        "orps xmm0, xmm1\n\t"
        ".att_syntax prefix\n\t");
}

__attribute__((used, noinline, noclone)) void scalar_float_forms(void) {
    __asm__(
        ".intel_syntax noprefix\n\t"
        "addss xmm0, xmm1\n\t"
        "addsd xmm0, xmm1\n\t"
        "subss xmm0, xmm1\n\t"
        "subsd xmm0, xmm1\n\t"
        "mulss xmm0, xmm1\n\t"
        "mulsd xmm0, xmm1\n\t"
        "divss xmm0, xmm1\n\t"
        "divsd xmm0, xmm1\n\t"
        "sqrtss xmm0, xmm1\n\t"
        "sqrtsd xmm0, xmm1\n\t"
        "comiss xmm0, xmm1\n\t"
        "comisd xmm0, xmm1\n\t"
        "ucomiss xmm0, xmm1\n\t"
        "ucomisd xmm0, xmm1\n\t"
        "cvtsi2ss xmm0, rax\n\t"
        "cvtsi2sd xmm0, rax\n\t"
        "cvtss2si rax, xmm0\n\t"
        "cvtsd2si rax, xmm0\n\t"
        "cvttss2si rax, xmm0\n\t"
        "cvttsd2si rax, xmm0\n\t"
        "cvtss2sd xmm0, xmm1\n\t"
        "cvtsd2ss xmm0, xmm1\n\t"
        ".att_syntax prefix\n\t");
}

__attribute__((used, noinline, noclone)) void string_forms(void) {
    __asm__(
        ".intel_syntax noprefix\n\t"
        "movsb\n\t"
        "movsw\n\t"
        "movsd\n\t"
        "movsq\n\t"
        "stosb\n\t"
        "stosw\n\t"
        "stosd\n\t"
        "stosq\n\t"
        "lodsb\n\t"
        "lodsw\n\t"
        "lodsd\n\t"
        "lodsq\n\t"
        "cmpsb\n\t"
        "cmpsw\n\t"
        "cmpsd\n\t"
        "cmpsq\n\t"
        "scasb\n\t"
        "scasw\n\t"
        "scasd\n\t"
        "scasq\n\t"
        "rep movsb\n\t"
        "rep movsq\n\t"
        "rep stosb\n\t"
        "rep stosq\n\t"
        "rep lodsb\n\t"
        "rep lodsq\n\t"
        "repe cmpsb\n\t"
        "repe cmpsq\n\t"
        "repne cmpsb\n\t"
        "repne cmpsq\n\t"
        "repe scasb\n\t"
        "repe scasq\n\t"
        "repne scasb\n\t"
        "repne scasq\n\t"
        ".att_syntax prefix\n\t");
}

__attribute__((used, noinline, noclone)) void atomic_forms(void) {
    __asm__(
        ".intel_syntax noprefix\n\t"
        "lock add qword ptr [rax], rbx\n\t"
        "lock bts qword ptr [rax], rcx\n\t"
        "lock xadd qword ptr [rax], rbx\n\t"
        "xchg qword ptr [rax], rbx\n\t"
        "cmpxchg qword ptr [rax], rbx\n\t"
        "cmpxchg8b qword ptr [rax]\n\t"
        "cmpxchg16b xmmword ptr [rax]\n\t"
        "lfence\n\t"
        "mfence\n\t"
        "sfence\n\t"
        ".att_syntax prefix\n\t");
}
