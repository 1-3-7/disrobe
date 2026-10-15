    .text

    .globl thunk_table_pick
    .type thunk_table_pick, @function
thunk_table_pick:
    pushl %ebx
    call __x86.get_pc_thunk.bx
    addl $_GLOBAL_OFFSET_TABLE_, %ebx
    movl 8(%esp), %eax
    andl $7, %eax
    movl thunk_table@GOTOFF(%ebx,%eax,4), %eax
    addl 8(%esp), %eax
    popl %ebx
    ret
    .size thunk_table_pick, .-thunk_table_pick

    .globl thunk_bump
    .type thunk_bump, @function
thunk_bump:
    call __x86.get_pc_thunk.cx
    addl $_GLOBAL_OFFSET_TABLE_, %ecx
    movl thunk_counter@GOT(%ecx), %ecx
    movl 4(%esp), %eax
    addl (%ecx), %eax
    movl %eax, (%ecx)
    xorl $5, %eax
    ret
    .size thunk_bump, .-thunk_bump

    .globl thunk_call_pop
    .type thunk_call_pop, @function
thunk_call_pop:
    pushl %esi
    call 1f
1:
    popl %esi
    addl $_GLOBAL_OFFSET_TABLE_+(.-1b), %esi
    movl 8(%esp), %eax
    andl $3, %eax
    movl thunk_table@GOTOFF(%esi,%eax,4), %ecx
    movl 8(%esp), %eax
    imull %ecx, %eax
    popl %esi
    ret
    .size thunk_call_pop, .-thunk_call_pop

    .section .text.__x86.get_pc_thunk.bx,"axG",@progbits,__x86.get_pc_thunk.bx,comdat
    .globl __x86.get_pc_thunk.bx
    .hidden __x86.get_pc_thunk.bx
    .type __x86.get_pc_thunk.bx, @function
__x86.get_pc_thunk.bx:
    movl (%esp), %ebx
    ret
    .size __x86.get_pc_thunk.bx, .-__x86.get_pc_thunk.bx

    .section .text.__x86.get_pc_thunk.cx,"axG",@progbits,__x86.get_pc_thunk.cx,comdat
    .globl __x86.get_pc_thunk.cx
    .hidden __x86.get_pc_thunk.cx
    .type __x86.get_pc_thunk.cx, @function
__x86.get_pc_thunk.cx:
    movl (%esp), %ecx
    ret
    .size __x86.get_pc_thunk.cx, .-__x86.get_pc_thunk.cx

    .data
    .p2align 2
thunk_table:
    .long 3, 1, 4, 1, 5, 9, 2, 6
    .globl thunk_counter
    .type thunk_counter, @object
thunk_counter:
    .long 0
    .size thunk_counter, 4

    .section .note.GNU-stack,"",@progbits
