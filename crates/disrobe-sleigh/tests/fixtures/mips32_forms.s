.set noreorder
.set nomips16
.set noat
.option pic0
.text
.globl mips32_forms
.ent mips32_forms
mips32_forms:
add $2, $3, $4
addu $5, $6, $7
addiu $8, $9, -12
sub $10, $11, $12
subu $13, $14, $15
and $16, $17, $18
or $19, $20, $21
xor $22, $23, $24
slt $25, $26, $27
sltu $2, $3, $4
lw $5, 16($6)
sw $7, -20($8)
lui $9, 0x1234
beq $2, $3, mips32_target
addiu $4, $4, 1
bne $5, $6, mips32_target
addu $7, $7, $8
j mips32_target
nop
jal mips32_target
nop
jr $31
nop
mult $10, $11
div $0, $12, $13
nop
mips32_target:
addu $2, $0, $3
.end mips32_forms
