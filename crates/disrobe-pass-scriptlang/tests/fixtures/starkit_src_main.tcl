package require Tcl 8.6
proc greet {name} {
    return "Hello, $name!"
}
proc add {a b} {
    return [expr {$a + $b}]
}
puts [greet disrobe]
puts [add 2 3]
