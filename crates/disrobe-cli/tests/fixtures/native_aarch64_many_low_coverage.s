.text
.global clean_arith
.type clean_arith, %function
clean_arith:
add x0, x0, x1
add x0, x0, x1
add x0, x0, x1
add x0, x0, x1
add x0, x0, x1
add x0, x0, x1
add x0, x0, x1
add x0, x0, x1
add x0, x0, x1
add x0, x0, x1
ret
.size clean_arith, .-clean_arith

.global mid_probe
.type mid_probe, %function
mid_probe:
add x0, x0, x1
add x0, x0, #1
add x0, x0, x2
mrs x1, tpidr_el0
svc #0
dmb ish
isb
msr tpidr_el0, x0
dc civac, x0
ret
.size mid_probe, .-mid_probe

.global system_probe_10
.type system_probe_10, %function
system_probe_10:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_10, .-system_probe_10

.global system_probe_09
.type system_probe_09, %function
system_probe_09:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_09, .-system_probe_09

.global system_probe_08
.type system_probe_08, %function
system_probe_08:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_08, .-system_probe_08

.global system_probe_07
.type system_probe_07, %function
system_probe_07:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_07, .-system_probe_07

.global system_probe_06
.type system_probe_06, %function
system_probe_06:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_06, .-system_probe_06

.global system_probe_05
.type system_probe_05, %function
system_probe_05:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_05, .-system_probe_05

.global system_probe_04
.type system_probe_04, %function
system_probe_04:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_04, .-system_probe_04

.global system_probe_03
.type system_probe_03, %function
system_probe_03:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_03, .-system_probe_03

.global system_probe_02
.type system_probe_02, %function
system_probe_02:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_02, .-system_probe_02

.global system_probe_01
.type system_probe_01, %function
system_probe_01:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_01, .-system_probe_01

.global system_probe_00
.type system_probe_00, %function
system_probe_00:
mrs x1, tpidr_el0
svc #0
ret
.size system_probe_00, .-system_probe_00

