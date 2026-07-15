.syntax unified
.arm
.text
.global arm32_a32_forms
.type arm32_a32_forms,%function
arm32_a32_forms:
add r0, r1, r2, lsl #3
sub r3, r4, #7
and r5, r6, r7, lsr #2
orr r8, r9, r10
eor r0, r1, r2, asr #1
mov r3, r4
movw r5, #0x1234
movt r5, #0x5678
mul r6, r7, r8
mla r9, r10, r11, r12
cmp r0, r1
ldr r2, [r3, #12]
str r4, [r5, #-8]
ldmia r6!, {r0-r3}
stmdb sp!, {r4-r7, lr}
b arm32_a32_target
bl arm32_a32_target
bx lr
arm32_a32_target:
push {r4-r7, lr}
pop {r4-r7, pc}
.size arm32_a32_forms, .-arm32_a32_forms
