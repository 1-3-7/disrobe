.text
.globl security_frame
.type security_frame, %function
security_frame:
    bti c
    paciasp
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x0, x1
    ldp x29, x30, [sp], #16
    autiasp
    ret
.size security_frame, .-security_frame
