.intel_syntax noprefix
.text
.global flattened_function

flattened_function:
    mov dword ptr [rbp - 4], 0
    jmp dispatcher
dispatcher:
    cmp dword ptr [rbp - 4], 0
    je case_a
    cmp dword ptr [rbp - 4], 1
    je case_b
    cmp dword ptr [rbp - 4], 2
    je case_c
    ret
case_a:
    mov eax, 1
    mov dword ptr [rbp - 4], 1
    jmp dispatcher
case_b:
    .byte 0x05
    .long 7
    mov dword ptr [rbp - 4], 2
    jmp dispatcher
case_c:
    ret
