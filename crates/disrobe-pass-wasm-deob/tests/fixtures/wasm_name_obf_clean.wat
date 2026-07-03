(module
  (global $accumulator (mut i32) (i32.const 0))
  (func $square (param $value i32) (result i32)
    local.get $value
    local.get $value
    i32.mul)
  (func $add (param $lhs i32) (param $rhs i32) (result i32)
    (local $sum i32)
    local.get $lhs
    local.get $rhs
    i32.add
    local.set $sum
    local.get $sum)
  (func $accumulate (param $delta i32) (result i32)
    (local $next i32)
    global.get $accumulator
    local.get $delta
    i32.add
    local.set $next
    local.get $next
    global.set $accumulator
    global.get $accumulator)
  (func $sum_of_squares (param $a i32) (param $b i32) (result i32)
    (local $sa i32)
    (local $sb i32)
    local.get $a
    call $square
    local.set $sa
    local.get $b
    call $square
    local.set $sb
    local.get $sa
    local.get $sb
    call $add)
  (export "accumulate" (func $accumulate))
  (export "sum_of_squares" (func $sum_of_squares)))
