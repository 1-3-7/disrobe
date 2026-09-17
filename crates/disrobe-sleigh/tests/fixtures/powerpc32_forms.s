.text
.globl powerpc32_forms
.type powerpc32_forms,@function
powerpc32_forms:
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
addi 13,14,7
b powerpc32_target
bl powerpc32_target
bl .+4
bclr 20,0,1
ba 4
bla 4
blr
bctr
bc 12,2,powerpc32_target
bc 4,6,powerpc32_target
bc 16,0,powerpc32_target
bc 10,5,powerpc32_target
mullw 24,25,26
divw 27,28,29
nop
powerpc32_target:
addi 30,31,1
.size powerpc32_forms,.-powerpc32_forms
