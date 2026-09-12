.text
.global clean_arith
.type clean_arith, %function
clean_arith:
add x0, x0, x1
add x0, x0, #1
sub x0, x0, x2
add x0, x0, #2
sub x0, x0, #3
add x0, x0, x1
sub x0, x0, x2
add x0, x0, #4
sub x0, x0, #5
add x0, x0, x1
ret
.size clean_arith, .-clean_arith

.global system_probe
.type system_probe, %function
system_probe:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe, .-system_probe
