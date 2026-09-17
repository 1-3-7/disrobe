.text
.globl powerpc64_forms
.type powerpc64_forms,@function
powerpc64_forms:
ld 3,0(4)
std 5,8(6)
rldicl 7,8,9,10
rldicr 9,10,11,12
cmpd 2,11,12
cmpld 3,13,14
mulld 15,16,17
divd 18,19,20
bc 12,2,powerpc64_target
bc 16,0,powerpc64_target
blr
powerpc64_target:
addi 21,22,7
add 3,4,5
subf 6,7,8
and 9,10,11
or 12,13,14
xor 15,16,17
slw 18,19,20
srw 21,22,23
cmpw 0,3,4
cmpwi 1,5,-7
lwz 3,12(4)
stw 5,-16(6)
lbz 7,3(8)
stb 9,-4(10)
li 11,-123
lis 12,0x1234
mullw 24,25,26
divw 27,28,29
nop
.size powerpc64_forms,.-powerpc64_forms
