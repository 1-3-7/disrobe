.section .text
.globl _start
.type _start,@function
_start:
.byte 0x52, 0x54, 0x52, 0x00
xorl %edi, %edi
movl $60, %eax
syscall
.size _start, .-_start

.section .rodata
.p2align 3
elf_metadata_start:
.byte 28
.ascii "ElfFixtureType"
.byte 28
.ascii "SharedMetadata"
elf_metadata_end:

.section .data
.p2align 3
.globl elf_ready_to_run_header
.type elf_ready_to_run_header,@object
elf_ready_to_run_header:
.long 0x00525452
.short 10
.short 1
.long 0
.short 2
.byte 24
.byte 1
.long 200
.long 1
.quad elf_metadata_start
.quad elf_metadata_end
.long 205
.long 1
.quad elf_cctor_start
.quad elf_cctor_end
.size elf_ready_to_run_header, .-elf_ready_to_run_header

.p2align 3
elf_cctor_start:
.byte 0
elf_cctor_end:

.section .note.GNU-stack,"",@progbits
