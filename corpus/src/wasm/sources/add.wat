(module
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    (local $acc i32)
    local.get $a
    local.get $b
    i32.add
    local.set $acc
    local.get $acc)
  (func $mul_add (export "mul_add") (param $a i32) (param $b i32) (param $c i32) (result i32)
    local.get $a
    local.get $b
    i32.mul
    local.get $c
    i32.add)
  (func $abs (export "abs") (param $x i32) (result i32)
    local.get $x
    i32.const 0
    i32.lt_s
    if (result i32)
      i32.const 0
      local.get $x
      i32.sub
    else
      local.get $x
    end))
