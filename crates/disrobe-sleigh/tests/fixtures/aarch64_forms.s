.text
.p2align 2
.global disrobe_sleigh_forms
.type disrobe_sleigh_forms, %function
disrobe_sleigh_forms:
add x0, x1, #1
add w0, w1, #1
adds x0, x1, #1
sub x0, x1, #1
subs x0, x1, #1
cmp x1, #1
cmn x1, #1
add x0, x1, x2, lsl #3
sub x0, x1, x2, asr #3
sub w0, w1, w2, lsr #3
mov sp, x0
and x0, x1, x2, lsr #3
and w0, w1, w2, lsl #3
ands x0, x1, x2
tst x1, x2
orr x0, x1, x2
eor x0, x1, x2
mov x0, x1
mov w0, w1
movz x0, #0x1234, lsl #16
movz w0, #0x1234
movn x0, #0x1234, lsl #16
movk x0, #0x5678, lsl #32
movk w0, #0x5678, lsl #16
lsl x0, x1, #5
lsl w0, w1, #5
lsr x0, x1, #5
lsr w0, w1, #5
asr x0, x1, #5
asr w0, w1, #5
ldr x0, [x1, #8]
str x0, [x1, #8]
ldr w0, [x1, #4]
str w0, [x1, #4]
ldp x0, x1, [x2, #16]
stp x0, x1, [x2, #16]
ldp x0, x1, [x2, #16]!
stp x0, x1, [x2, #-16]!
ldp x0, x1, [x2], #16
stp x0, x1, [x2], #-16
ldp w0, w1, [x2, #8]
stp w0, w1, [x2, #8]
mul x0, x1, x2
mul w0, w1, w2
madd x0, x1, x2, x3
madd w0, w1, w2, w3
msub x0, x1, x2, x3
msub w0, w1, w2, w3
csel x0, x1, x2, eq
csel w0, w1, w2, eq
b 1f
bl 1f
b.ne 1f
cbz x0, 1f
cbz w0, 1f
cbnz x0, 1f
br x0
blr x0
blr x30
ret x30
adr x0, 1f
adrp x0, 1f
nop
1:
ret
.size disrobe_sleigh_forms, .-disrobe_sleigh_forms
