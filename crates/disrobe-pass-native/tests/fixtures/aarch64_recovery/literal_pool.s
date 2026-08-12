.text
.p2align 2
.globl literal_f
.type literal_f,%function
literal_f:
    ldr s0, .Lliteral_f
    ret
.size literal_f, .-literal_f
.p2align 2
.Lliteral_f:
    .word 0x3fc00000

.p2align 2
.globl literal_d
.type literal_d,%function
literal_d:
    ldr d0, .Lliteral_d
    ret
.size literal_d, .-literal_d
.p2align 3
.Lliteral_d:
    .xword 0x8000000000000000
