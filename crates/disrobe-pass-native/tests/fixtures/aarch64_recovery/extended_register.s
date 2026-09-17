.text

.global cmp_uxtb_eq
.type cmp_uxtb_eq, %function
cmp_uxtb_eq:
    cmp x0, w1, uxtb
    cset w0, eq
    ret

.global subs_uxtb_eq
.type subs_uxtb_eq, %function
subs_uxtb_eq:
    subs x2, x0, w1, uxtb
    cset w0, eq
    ret

.global cmn_sxtb_mi
.type cmn_sxtb_mi, %function
cmn_sxtb_mi:
    cmn x0, w1, sxtb
    cset w0, mi
    ret

.global adds_sxtb_mi
.type adds_sxtb_mi, %function
adds_sxtb_mi:
    adds x2, x0, w1, sxtb
    cset w0, mi
    ret

.global adds_uxtb_cs
.type adds_uxtb_cs, %function
adds_uxtb_cs:
    adds x0, x0, w1, uxtb #1
    cset w0, cs
    ret

.global nat001_adds_uxtb_value
.type nat001_adds_uxtb_value, %function
nat001_adds_uxtb_value:
    adds x0, x0, w1, uxtb #1
    ret

.global nat001_adds_uxtb_n
.type nat001_adds_uxtb_n, %function
nat001_adds_uxtb_n:
    adds x2, x0, w1, uxtb #1
    cset w0, mi
    ret

.global nat001_adds_uxtb_z
.type nat001_adds_uxtb_z, %function
nat001_adds_uxtb_z:
    adds x2, x0, w1, uxtb #1
    cset w0, eq
    ret

.global nat001_adds_uxtb_c
.type nat001_adds_uxtb_c, %function
nat001_adds_uxtb_c:
    adds x2, x0, w1, uxtb #1
    cset w0, cs
    ret

.global nat001_adds_uxtb_v
.type nat001_adds_uxtb_v, %function
nat001_adds_uxtb_v:
    adds x2, x0, w1, uxtb #1
    cset w0, vs
    ret

.global nat001_sp_refusal
.type nat001_sp_refusal, %function
nat001_sp_refusal:
    add sp, sp, w1, uxtb
    ret

.global adds_uxtb_hi
.type adds_uxtb_hi, %function
adds_uxtb_hi:
    adds x0, x0, w1, uxtb #1
    cset w0, hi
    ret

.global adds_uxtb_ls
.type adds_uxtb_ls, %function
adds_uxtb_ls:
    adds x0, x0, w1, uxtb #1
    cset w0, ls
    ret

.global add_uxth
.type add_uxth, %function
add_uxth:
    add x0, x0, w1, uxth #1
    ret

.global subs_sxth_vs
.type subs_sxth_vs, %function
subs_sxth_vs:
    subs x0, x0, w1, sxth #2
    cset w0, vs
    ret

.global add_uxtw
.type add_uxtw, %function
add_uxtw:
    add x0, x0, w1, uxtw #3
    ret

.global sub_sxtw
.type sub_sxtw, %function
sub_sxtw:
    sub x0, x0, w1, sxtw #4
    ret

.global add_uxtx
.type add_uxtx, %function
add_uxtx:
    add x0, x0, x1, uxtx
    ret

.global sub_sxtx
.type sub_sxtx, %function
sub_sxtx:
    sub x0, x0, x1, sxtx
    ret

.global cmp_w_uxtb_eq
.type cmp_w_uxtb_eq, %function
cmp_w_uxtb_eq:
    cmp w0, w1, uxtb
    cset w0, eq
    ret

.global cmn_w_sxtb_mi
.type cmn_w_sxtb_mi, %function
cmn_w_sxtb_mi:
    cmn w0, w1, sxtb
    cset w0, mi
    ret

.global adds_w_uxth_cs
.type adds_w_uxth_cs, %function
adds_w_uxth_cs:
    adds w0, w0, w1, uxth #1
    cset w0, cs
    ret

.global subs_w_sxth_vs
.type subs_w_sxth_vs, %function
subs_w_sxth_vs:
    subs w0, w0, w1, sxth #2
    cset w0, vs
    ret
