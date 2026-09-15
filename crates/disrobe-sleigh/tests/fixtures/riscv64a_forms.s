.option norvc
.option norelax
.text
.globl riscv64a_forms
.type riscv64a_forms,@function
riscv64a_forms:
lr.w a0,(a1)
sc.w a2,a3,(a4)
amoadd.w.aq a5,a6,(a7)
lr.d.rl s0,(s1)
sc.d.aqrl s2,s3,(s4)
amoswap.d s5,s6,(s7)
amoadd.d s8,s9,(s10)
amoand.d s11,t3,(t4)
amoor.d t5,t6,(a0)
amoxor.d a1,a2,(a3)
amomin.d a4,a5,(a6)
amomax.d a7,s0,(s1)
.size riscv64a_forms,.-riscv64a_forms
