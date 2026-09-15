.text
.global scalar_take
.type scalar_take, %function
scalar_take:
ldr x8, [x0]
ldr d0, [x8], #8
str x8, [x0]
ret
.size scalar_take, .-scalar_take

.global scalar_put
.type scalar_put, %function
scalar_put:
ldr x8, [x1]
str d0, [x8], #8
str x8, [x1]
ret
.size scalar_put, .-scalar_put
