.text
.option norvc
.globl forms
forms:
flw ft0, 12(a0)
fsw ft1, -16(a1)
fadd.s ft2, ft3, ft4, rne
fsub.s ft5, ft6, ft7, rtz
fmul.s fa0, fa1, fa2, rdn
fdiv.s fa3, fa4, fa5, rup
fmv.w.x ft0, a0
fmv.x.w a1, ft1
fcvt.s.w ft2, a2, rne
fcvt.w.s a3, ft3, rtz
fmadd.s ft4, ft5, ft6, ft7, rne
feq.s a4, fa0, fa1
flt.s a5, fa2, fa3
fle.s a6, fa4, fa5
fsqrt.s fa6, fa7, rne
fld ft8, 24(a2)
fsd ft9, -32(a3)
fadd.d ft10, ft11, fs0, rne
fsub.d fs1, fa0, fa1, rtz
fmul.d fa2, fa3, fa4, rdn
fdiv.d fa5, fa6, fa7, rup
fcvt.d.s fs2, fs3
fcvt.s.d fs4, fs5, rne
fmadd.d fs6, fs7, fs8, fs9, rne
feq.d a7, fs10, fs11
flt.d s0, ft8, ft9
fle.d s1, ft10, ft11
fsqrt.d fa0, fa1, rne
csrrw a0, 0x305, a1
csrrs a2, 0xc00, a3
csrrc a4, 0x340, a5
csrrwi a6, 0x341, 3
csrrsi a7, 0x342, 4
csrrci s0, 0x343, 5
fence rw, rw
fence.i
ret
