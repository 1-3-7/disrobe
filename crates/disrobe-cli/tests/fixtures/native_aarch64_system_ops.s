.text
.global sysops_probe
.type sysops_probe, %function
sysops_probe:
add x0, x0, #1
mrs x1, tpidr_el0
dmb ish
add x0, x0, x1
svc #0
isb
msr tpidr_el0, x0
dc civac, x0
ret
.size sysops_probe, .-sysops_probe
