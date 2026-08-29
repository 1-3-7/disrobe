.text

.globl frame_fixed_offset
.type frame_fixed_offset, %function
frame_fixed_offset:
    sub sp, sp, #32
    stp x29, x30, [sp, #16]
    add x29, sp, #16
    mov x0, x1
    ldp x29, x30, [sp, #16]
    add sp, sp, #32
    ret
.size frame_fixed_offset, .-frame_fixed_offset

.globl frame_scaled_fixed
.type frame_scaled_fixed, %function
frame_scaled_fixed:
    sub sp, sp, #2, lsl #12
    stp x29, x30, [sp, #16]
    add x29, sp, #16
    mov x0, x1
    ldp x29, x30, [sp, #16]
    add sp, sp, #2, lsl #12
    ret
.size frame_scaled_fixed, .-frame_scaled_fixed

.globl frame_scaled_mismatch
.type frame_scaled_mismatch, %function
frame_scaled_mismatch:
    sub sp, sp, #2, lsl #12
    stp x29, x30, [sp, #16]
    add x29, sp, #16
    mov x0, x1
    ldp x29, x30, [sp, #16]
    add sp, sp, #1, lsl #12
    ret
.size frame_scaled_mismatch, .-frame_scaled_mismatch

.globl frame_multiple_returns
.type frame_multiple_returns, %function
frame_multiple_returns:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    cbz x0, .Lzero
    mov x0, x1
    ldp x29, x30, [sp], #16
    ret
.Lzero:
    mov x0, #0
    ldp x29, x30, [sp], #16
    ret
.size frame_multiple_returns, .-frame_multiple_returns

.globl frame_multiple_return_mismatch
.type frame_multiple_return_mismatch, %function
frame_multiple_return_mismatch:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    cbz x0, .Lmismatch
    ldp x29, x30, [sp], #16
    ret
.Lmismatch:
    ldp x29, x30, [sp], #32
    ret
.size frame_multiple_return_mismatch, .-frame_multiple_return_mismatch

.globl frame_callee_saved_pairs
.type frame_callee_saved_pairs, %function
frame_callee_saved_pairs:
    stp x29, x30, [sp, #-48]!
    stp x19, x20, [sp, #16]
    stp d8, d9, [sp, #32]
    mov x29, sp
    mov x19, #0
    mov x20, #0
    fmov d8, x0
    fmov d9, x0
    mov x0, x1
    ldp d8, d9, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #48
    ret
.size frame_callee_saved_pairs, .-frame_callee_saved_pairs

.globl frame_swapped_integer_pair
.type frame_swapped_integer_pair, %function
frame_swapped_integer_pair:
    stp x19, x20, [sp, #-16]!
    mov x19, #0
    mov x20, #0
    ldp x20, x19, [sp], #16
    ret
.size frame_swapped_integer_pair, .-frame_swapped_integer_pair

.globl frame_missing_integer_pair
.type frame_missing_integer_pair, %function
frame_missing_integer_pair:
    stp x19, x20, [sp, #-16]!
    mov x19, #0
    mov x20, #0
    add sp, sp, #16
    ret
.size frame_missing_integer_pair, .-frame_missing_integer_pair

.globl frame_swapped_fp_pair
.type frame_swapped_fp_pair, %function
frame_swapped_fp_pair:
    stp d8, d9, [sp, #-16]!
    fmov d8, x0
    fmov d9, x0
    ldp d9, d8, [sp], #16
    ret
.size frame_swapped_fp_pair, .-frame_swapped_fp_pair

.globl frame_missing_fp_pair
.type frame_missing_fp_pair, %function
frame_missing_fp_pair:
    stp d8, d9, [sp, #-16]!
    fmov d8, x0
    fmov d9, x0
    add sp, sp, #16
    ret
.size frame_missing_fp_pair, .-frame_missing_fp_pair
