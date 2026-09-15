.arch armv8.5-a+fp16+jsconv
.text
.macro FN name
.p2align 2
.globl \name
.type \name,%function
\name:
.endm

.macro END name
.size \name, .-\name
.endm

FN a_fadd_s
    fadd s0, s0, s1
    ret
END a_fadd_s
FN a_fadd_d
    fadd d0, d0, d1
    ret
END a_fadd_d
FN a_fadd_h
    fadd h0, h0, h1
    ret
END a_fadd_h
FN a_fsub_s
    fsub s0, s0, s1
    ret
END a_fsub_s
FN a_fmul_d
    fmul d0, d0, d1
    ret
END a_fmul_d
FN a_fdiv_h
    fdiv h0, h0, h1
    ret
END a_fdiv_h
FN a_fabd_s
    fabd s0, s0, s1
    ret
END a_fabd_s
FN a_fnmul_d
    fnmul d0, d0, d1
    ret
END a_fnmul_d
FN a_fsqrt_h
    fsqrt h0, h0
    ret
END a_fsqrt_h
FN a_fneg_s
    fneg s0, s0
    ret
END a_fneg_s
FN a_fabs_d
    fabs d0, d0
    ret
END a_fabs_d
FN a_fmax_s
    fmax s0, s0, s1
    ret
END a_fmax_s
FN a_fmin_d
    fmin d0, d0, d1
    ret
END a_fmin_d
FN a_fmaxnm_h
    fmaxnm h0, h0, h1
    ret
END a_fmaxnm_h
FN a_fminnm_s
    fminnm s0, s0, s1
    ret
END a_fminnm_s

FN a_fmul_h
    fmul h0, h0, h1
    ret
END a_fmul_h
FN a_fsub_h
    fsub h0, h0, h1
    ret
END a_fsub_h
FN a_fabd_d
    fabd d0, d0, d1
    ret
END a_fabd_d
FN a_fnmul_s
    fnmul s0, s0, s1
    ret
END a_fnmul_s
FN a_fneg_h
    fneg h0, h0
    ret
END a_fneg_h
FN a_fabs_h
    fabs h0, h0
    ret
END a_fabs_h
FN a_fmax_h
    fmax h0, h0, h1
    ret
END a_fmax_h
FN a_fmin_s
    fmin s0, s0, s1
    ret
END a_fmin_s
FN a_fmaxnm_d
    fmaxnm d0, d0, d1
    ret
END a_fmaxnm_d
FN a_fminnm_h
    fminnm h0, h0, h1
    ret
END a_fminnm_h
FN a_fsqrt_s
    fsqrt s0, s0
    ret
END a_fsqrt_s
FN a_fsqrt_d
    fsqrt d0, d0
    ret
END a_fsqrt_d
FN b_fmadd_s
    fmadd s0, s0, s1, s2
    ret
END b_fmadd_s
FN b_fmsub_d
    fmsub d0, d0, d1, d2
    ret
END b_fmsub_d
FN b_fnmadd_h
    fnmadd h0, h0, h1, h2
    ret
END b_fnmadd_h
FN b_fnmsub_d
    fnmsub d0, d0, d1, d2
    ret
END b_fnmsub_d

FN b_fmadd_d
    fmadd d0, d0, d1, d2
    ret
END b_fmadd_d
FN b_fmsub_h
    fmsub h0, h0, h1, h2
    ret
END b_fmsub_h
FN b_fnmadd_s
    fnmadd s0, s0, s1, s2
    ret
END b_fnmadd_s
FN b_fnmsub_h
    fnmsub h0, h0, h1, h2
    ret
END b_fnmsub_h
FN c_fcmp_s
    fcmp s0, s1
    cset w0, gt
    ret
END c_fcmp_s
FN c_fcmp_zero_d
    fcmp d0, #0.0
    cset w0, eq
    ret
END c_fcmp_zero_d
FN c_fcmpe_d
    fcmpe d0, d1
    cset w0, mi
    ret
END c_fcmpe_d
FN c_fcmpe_zero_s
    fcmpe s0, #0.0
    cset w0, ne
    ret
END c_fcmpe_zero_s
FN c_fcmp_h
    fcmp h0, h1
    cset w0, gt
    ret
END c_fcmp_h
FN c_fccmp_d
    fcmp d0, d1
    fccmp d0, d1, #4, gt
    cset w0, eq
    ret
END c_fccmp_d
FN c_fccmpe_s
    fcmp s0, s1
    fccmpe s0, s1, #0, ne
    cset w0, mi
    ret
END c_fccmpe_s
FN c_fcsel_d
    fcmp d0, d1
    fcsel d0, d0, d1, gt
    ret
END c_fcsel_d
FN c_fcsel_h
    fcmp h0, h1
    fcsel h0, h0, h1, gt
    ret
END c_fcsel_h

FN c_fcmp_d
    fcmp d0, d1
    cset w0, lt
    ret
END c_fcmp_d
FN c_fcmp_zero_h
    fcmp h0, #0.0
    cset w0, eq
    ret
END c_fcmp_zero_h
FN c_fcmpe_h
    fcmpe h0, h1
    cset w0, mi
    ret
END c_fcmpe_h
FN c_fccmp_h
    fcmp h0, h1
    fccmp h0, h1, #4, gt
    cset w0, eq
    ret
END c_fccmp_h
FN c_fccmpe_d
    fcmp d0, d1
    fccmpe d0, d1, #2, ne
    cset w0, mi
    ret
END c_fccmpe_d
FN c_fcsel_s
    fcmp s0, s1
    fcsel s0, s0, s1, mi
    ret
END c_fcsel_s
FN d_fcvt_s_to_d
    fcvt d0, s0
    ret
END d_fcvt_s_to_d
FN d_fcvt_d_to_s
    fcvt s0, d0
    ret
END d_fcvt_d_to_s
FN d_fcvt_h_to_s
    fcvt s0, h0
    ret
END d_fcvt_h_to_s
FN d_fcvt_s_to_h
    fcvt h0, s0
    ret
END d_fcvt_s_to_h
FN d_fcvt_h_to_d
    fcvt d0, h0
    ret
END d_fcvt_h_to_d
FN d_fcvt_d_to_h
    fcvt h0, d0
    ret
END d_fcvt_d_to_h

FN e_fcvtzs_w_s
    fcvtzs w0, s0
    ret
END e_fcvtzs_w_s
FN e_fcvtzs_x_d
    fcvtzs x0, d0
    ret
END e_fcvtzs_x_d
FN e_fcvtzu_w_d
    fcvtzu w0, d0
    ret
END e_fcvtzu_w_d
FN e_fcvtzu_x_h
    fcvtzu x0, h0
    ret
END e_fcvtzu_x_h
FN e_fcvtns_w_s
    fcvtns w0, s0
    ret
END e_fcvtns_w_s
FN e_fcvtnu_x_d
    fcvtnu x0, d0
    ret
END e_fcvtnu_x_d
FN e_fcvtms_w_d
    fcvtms w0, d0
    ret
END e_fcvtms_w_d
FN e_fcvtmu_x_s
    fcvtmu x0, s0
    ret
END e_fcvtmu_x_s
FN e_fcvtps_w_s
    fcvtps w0, s0
    ret
END e_fcvtps_w_s
FN e_fcvtpu_x_d
    fcvtpu x0, d0
    ret
END e_fcvtpu_x_d
FN e_fcvtas_w_d
    fcvtas w0, d0
    ret
END e_fcvtas_w_d
FN e_fcvtau_x_s
    fcvtau x0, s0
    ret
END e_fcvtau_x_s
FN e_fcvtzs_fixed_w_d
    fcvtzs w0, d0, #3
    ret
END e_fcvtzs_fixed_w_d
FN e_fcvtzu_fixed_x_s
    fcvtzu x0, s0, #7
    ret
END e_fcvtzu_fixed_x_s
FN e_fjcvtzs
    fjcvtzs w0, d0
    ret
END e_fjcvtzs

FN e_fcvtzs_w_h
    fcvtzs w0, h0
    ret
END e_fcvtzs_w_h
FN e_fcvtas_x_h
    fcvtas x0, h0
    ret
END e_fcvtas_x_h
FN e_fcvtau_w_h
    fcvtau w0, h0
    ret
END e_fcvtau_w_h
FN e_fcvtns_x_h
    fcvtns x0, h0
    ret
END e_fcvtns_x_h
FN e_fcvtnu_w_h
    fcvtnu w0, h0
    ret
END e_fcvtnu_w_h
FN e_fcvtms_x_h
    fcvtms x0, h0
    ret
END e_fcvtms_x_h
FN e_fcvtmu_w_h
    fcvtmu w0, h0
    ret
END e_fcvtmu_w_h
FN e_fcvtps_x_h
    fcvtps x0, h0
    ret
END e_fcvtps_x_h
FN e_fcvtpu_w_h
    fcvtpu w0, h0
    ret
END e_fcvtpu_w_h
FN e_fcvtzs_fixed_x_h
    fcvtzs x0, h0, #4
    ret
END e_fcvtzs_fixed_x_h
FN e_fcvtzu_fixed_w_h
    fcvtzu w0, h0, #2
    ret
END e_fcvtzu_fixed_w_h
FN f_scvtf_s_w
    scvtf s0, w0
    ret
END f_scvtf_s_w
FN f_scvtf_d_x
    scvtf d0, x0
    ret
END f_scvtf_d_x
FN f_ucvtf_s_x
    ucvtf s0, x0
    ret
END f_ucvtf_s_x
FN f_ucvtf_h_w
    ucvtf h0, w0
    ret
END f_ucvtf_h_w
FN f_scvtf_fixed_d_w
    scvtf d0, w0, #5
    ret
END f_scvtf_fixed_d_w
FN f_ucvtf_fixed_s_x
    ucvtf s0, x0, #9
    ret
END f_ucvtf_fixed_s_x

FN f_scvtf_h_x
    scvtf h0, x0
    ret
END f_scvtf_h_x
FN f_scvtf_s_x
    scvtf s0, x0
    ret
END f_scvtf_s_x
FN f_ucvtf_d_w
    ucvtf d0, w0
    ret
END f_ucvtf_d_w
FN f_scvtf_fixed_h_w
    scvtf h0, w0, #3
    ret
END f_scvtf_fixed_h_w
FN f_ucvtf_fixed_h_x
    ucvtf h0, x0, #6
    ret
END f_ucvtf_fixed_h_x
FN g_frinta_s
    frinta s0, s0
    ret
END g_frinta_s
FN g_frinti_d
    frinti d0, d0
    ret
END g_frinti_d
FN g_frintm_s
    frintm s0, s0
    ret
END g_frintm_s
FN g_frintn_d
    frintn d0, d0
    ret
END g_frintn_d
FN g_frintp_h
    frintp h0, h0
    ret
END g_frintp_h
FN g_frintx_d
    frintx d0, d0
    ret
END g_frintx_d
FN g_frintz_s
    frintz s0, s0
    ret
END g_frintz_s
FN g_frint32z_s
    frint32z s0, s0
    ret
END g_frint32z_s
FN g_frint32x_d
    frint32x d0, d0
    ret
END g_frint32x_d
FN g_frint64z_d
    frint64z d0, d0
    ret
END g_frint64z_d
FN g_frint64x_s
    frint64x s0, s0
    ret
END g_frint64x_s

FN g_frinta_d
    frinta d0, d0
    ret
END g_frinta_d
FN g_frinta_h
    frinta h0, h0
    ret
END g_frinta_h
FN g_frintm_h
    frintm h0, h0
    ret
END g_frintm_h
FN g_frintm_d
    frintm d0, d0
    ret
END g_frintm_d
FN g_frintn_s
    frintn s0, s0
    ret
END g_frintn_s
FN g_frintn_h
    frintn h0, h0
    ret
END g_frintn_h
FN g_frintz_d
    frintz d0, d0
    ret
END g_frintz_d
FN g_frintz_h
    frintz h0, h0
    ret
END g_frintz_h
FN g_frintp_s
    frintp s0, s0
    ret
END g_frintp_s
FN g_frintp_d
    frintp d0, d0
    ret
END g_frintp_d
FN g_frinti_h
    frinti h0, h0
    ret
END g_frinti_h
FN g_frintx_h
    frintx h0, h0
    ret
END g_frintx_h
FN h_fmov_reg_d
    fmov d0, d1
    ret
END h_fmov_reg_d
FN h_fmov_reg_h
    fmov h0, h1
    ret
END h_fmov_reg_h
FN h_fmov_x_from_d
    fmov x0, d0
    ret
END h_fmov_x_from_d
FN h_fmov_d_from_x
    fmov d0, x0
    ret
END h_fmov_d_from_x
FN h_fmov_w_from_s
    fmov w0, s0
    ret
END h_fmov_w_from_s
FN h_fmov_s_from_w
    fmov s0, w0
    ret
END h_fmov_s_from_w
FN h_fmov_imm_d
    fmov d0, #1.0
    ret
END h_fmov_imm_d
FN h_fmov_imm_s
    fmov s0, #-2.5
    ret
END h_fmov_imm_s
FN h_fmov_imm_h
    fmov h0, #1.0
    ret
END h_fmov_imm_h
FN h_fmov_top_half
    fmov x0, v0.d[1]
    ret
END h_fmov_top_half

FN h_fmov_w_from_h
    fmov w0, h0
    ret
END h_fmov_w_from_h
FN h_fmov_h_from_w
    fmov h0, w0
    ret
END h_fmov_h_from_w
FN h_fmov_x_from_h
    fmov x0, h0
    ret
END h_fmov_x_from_h
FN h_fmov_h_from_x
    fmov h0, x0
    ret
END h_fmov_h_from_x
FN i_ldr_s
    ldr s0, [x0]
    ret
END i_ldr_s
FN i_ldr_d_off
    ldr d0, [x0, #16]
    ret
END i_ldr_d_off
FN i_ldr_h
    ldr h0, [x0]
    ret
END i_ldr_h
FN i_ldr_q
    ldr q0, [x0]
    ret
END i_ldr_q
FN i_str_d
    str d0, [x0]
    ret
END i_str_d
FN i_ldur_s
    ldur s0, [x0, #-4]
    ret
END i_ldur_s
FN i_stur_d
    stur d0, [x0, #-8]
    ret
END i_stur_d
FN i_ldr_pre_d
    ldr d0, [x0, #8]!
    ret
END i_ldr_pre_d
FN i_ldr_post_d
    ldr d0, [x0], #8
    ret
END i_ldr_post_d
FN i_ldr_lit_s
    ldr s0, .Lpool_s
    ret
.p2align 2
.Lpool_s:
    .word 0x3fc00000
END i_ldr_lit_s
FN i_ldr_lit_d
    ldr d0, .Lpool_d
    ret
.p2align 3
.Lpool_d:
    .xword 0x3ff8000000000000
END i_ldr_lit_d

FN i_str_s
    str s0, [x0]
    ret
END i_str_s
FN i_str_h
    str h0, [x0]
    ret
END i_str_h
FN i_ldur_d
    ldur d0, [x0, #-8]
    ret
END i_ldur_d
FN i_ldur_h
    ldur h0, [x0, #-2]
    ret
END i_ldur_h
FN i_stur_s
    stur s0, [x0, #-4]
    ret
END i_stur_s
FN i_str_pre_d
    str d0, [x0, #8]!
    ret
END i_str_pre_d
FN i_str_post_s
    str s0, [x0], #4
    ret
END i_str_post_s
FN j_stp_d
    stp d8, d9, [sp, #-16]!
    ldp d8, d9, [sp], #16
    ret
END j_stp_d
FN j_ldp_s
    ldp s0, s1, [x0]
    ret
END j_ldp_s
FN j_ldp_q
    ldp q0, q1, [x0]
    ret
END j_ldp_q
FN j_str_d_pre
    str d8, [sp, #-16]!
    ldr d8, [sp], #16
    ret
END j_str_d_pre

FN j_ldp_d
    ldp d0, d1, [x0]
    ret
END j_ldp_d
FN j_stp_s
    stp s0, s1, [x0]
    ret
END j_stp_s
FN k_callee_saved_v16
    fadd d16, d0, d1
    fmul d0, d16, d16
    ret
END k_callee_saved_v16
FN k_high_v31
    fadd s31, s0, s1
    fmov s0, s31
    ret
END k_high_v31
