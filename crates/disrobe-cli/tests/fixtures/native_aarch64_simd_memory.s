.text
.global simd_memory_forms
.type simd_memory_forms, %function
simd_memory_forms:
ldur b0, [x0, #-8]
stur b0, [x1, #8]
ldur h1, [x0]
stur h1, [x1]
ldur s2, [x0, #4]
stur s2, [x1, #-4]
ldur d3, [x0, #8]
stur d3, [x1, #16]
ldur q4, [x0, #-16]
stur q4, [x1, #32]
ldr s5, [x0, x2]
str s5, [x1, x2]
ldr d6, [x0, w2, uxtw]
str d6, [x1, w2, uxtw]
ldr q7, [x0, w3, sxtw #4]
str q7, [x1, w3, sxtw #4]
ldr d8, [x0, x3, lsl #3]
str d8, [x1, x3, sxtx]
ldp s9, s10, [x0]
stp s9, s10, [x1]
ldp d11, d12, [x0, #16]
stp d11, d12, [x1, #16]
ldp q13, q14, [x0], #32
stp q13, q14, [x1], #32
ldp d15, d16, [x0, #24]!
stp d15, d16, [x1, #24]!
ret
.size simd_memory_forms, .-simd_memory_forms

.global scalar_memory_tail
.type scalar_memory_tail, %function
scalar_memory_tail:
ldur x4, [x0, #-8]
ldr x5, [x0], #16
str x5, [x1, #8]!
add x0, x4, x5
ret
.size scalar_memory_tail, .-scalar_memory_tail
