.option norvc
.option norelax
.text
.globl riscv64_forms
.type riscv64_forms,@function
riscv64_forms:
addi a0, a1, -7
add a2, a3, a4
sub a5, a6, a7
and t0, t1, t2
or s0, s1, s2
xor s3, s4, s5
sll s6, s7, s8
srl s9, s10, s11
sra t3, t4, t5
slt t6, a0, a1
lw a0, 12(a1)
sw a2, -16(a3)
ld a3, 24(a4)
sd a5, -32(a6)
lui a4, 0x12345
auipc a5, 0x23456
beq a0, a1, riscv64_target
bne a2, a3, riscv64_target
blt a4, a5, riscv64_target
bge a6, a7, riscv64_target
jal ra, riscv64_target
jalr a0, 4(a1)
mul a0, a1, a2
mulh a3, a4, a5
mulhsu a6, a7, s0
mulhu s1, s2, s3
div s4, s5, s6
divu s7, s8, s9
rem s10, s11, t3
remu t4, t5, t6
nop
ret
riscv64_target:
addi a0, a0, 1
.size riscv64_forms, .-riscv64_forms
