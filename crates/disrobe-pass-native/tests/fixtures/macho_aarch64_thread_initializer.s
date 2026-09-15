.section __TEXT,__text,regular,pure_instructions
.p2align 2
_initialize_thread:
    mov w0, #41
    ret

.globl _main
.p2align 2
_main:
    mov w0, #0
    ret

.section __DATA,__thread_init,thread_local_init_function_pointers
.p2align 3
.quad _initialize_thread
