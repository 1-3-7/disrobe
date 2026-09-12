.syntax unified
.thumb
.text
.global arm32_thumb_forms
.thumb_func
.type arm32_thumb_forms,%function
arm32_thumb_forms:
adds r0, r1, r2
subs r3, #1
ands r0, r1
orrs r2, r3
eors r4, r5
lsls r6, r7, #3
movs r0, #42
movw r4, #0x1234
movt r4, #0x5678
muls r0, r1, r0
cmp r2, r3
ldr r0, [r1, #12]
str r2, [r3, #8]
ldmia r4!, {r0-r3}
stmia r5!, {r0-r3}
b.n arm32_thumb_target
bl arm32_thumb_target
bx lr
arm32_thumb_target:
push {r4-r7, lr}
pop {r4-r7, pc}
mov r0, pc
mov pc, r0
add pc, r0
.size arm32_thumb_forms, .-arm32_thumb_forms
