.option norvc
.option norelax
.text
.globl riscv32a_forms
.type riscv32a_forms,@function
riscv32a_forms:
lr.w a0,(a1)
lr.w.aq a2,(a3)
sc.w.rl a4,a5,(a6)
amoswap.w a7,s0,(s1)
amoadd.w.aqrl s2,s3,(s4)
amoand.w s5,s6,(s7)
amoor.w s8,s9,(s10)
amoxor.w s11,t3,(t4)
amomin.w t5,t6,(a0)
amomax.w a1,a2,(a3)
.size riscv32a_forms,.-riscv32a_forms
