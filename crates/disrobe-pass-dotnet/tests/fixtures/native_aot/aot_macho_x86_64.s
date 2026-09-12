.section __TEXT,__text,regular,pure_instructions
.globl _start
_start:
.byte 0x52, 0x54, 0x52, 0x00
retq

.section __TEXT,__const
.p2align 3
macho_metadata_start:
.byte 32
.ascii "MachOFixtureType"
.byte 28
.ascii "SharedMetadata"
macho_metadata_end:

.section __DATA,__data
.p2align 3
.globl _macho_ready_to_run_header
_macho_ready_to_run_header:
.long 0x00525452
.short 26
.short 0
.long 0
.short 2
.byte 16
.byte 1
.long 200
.long macho_metadata_end - macho_metadata_start
.quad macho_metadata_start
.long 205
.long macho_cctor_end - macho_cctor_start
.quad macho_cctor_start

.p2align 3
macho_cctor_start:
.byte 0
macho_cctor_end:
