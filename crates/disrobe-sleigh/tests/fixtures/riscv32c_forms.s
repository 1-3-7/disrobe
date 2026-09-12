.option rvc
.option norelax
.text
.globl riscv32c_forms
.type riscv32c_forms,@function
riscv32c_forms:
c.addi a0,-7
c.li a1,9
c.lw a2,12(a3)
c.sw a4,16(a5)
c.j riscv32c_target
c.jal riscv32c_target
c.jr a0
c.jalr a1
c.beqz a2,riscv32c_target
c.bnez a3,riscv32c_target
c.mv a4,a5
c.add a0,a1
c.nop
c.addi4spn a2,sp,64
c.lwsp a3,20(sp)
c.swsp a4,24(sp)
c.and a0,a1
c.or a2,a3
riscv32c_target:
c.addi a0,1
.size riscv32c_forms,.-riscv32c_forms
