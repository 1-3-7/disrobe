(module
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (func $fib (export "fib") (param $n i32) (result i32)
    local.get $n
    i32.const 2
    i32.lt_s
    if (result i32)
      local.get $n
    else
      local.get $n
      i32.const 1
      i32.sub
      call $fib
      local.get $n
      i32.const 2
      i32.sub
      call $fib
      i32.add
    end)
  (func $classify (export "classify") (param $x i32) (result i32)
    local.get $x
    i32.const 0
    i32.lt_s
    if (result i32)
      i32.const -1
    else
      local.get $x
      i32.eqz
      if (result i32)
        i32.const 0
      else
        i32.const 1
      end
    end)
  (func $sum_to (export "sum_to") (param $n i32) (result i32)
    (local $i i32)
    (local $acc i32)
    i32.const 0
    local.set $acc
    i32.const 0
    local.set $i
    block $exit
      loop $loop
        local.get $i
        local.get $n
        i32.ge_s
        br_if $exit
        local.get $acc
        local.get $i
        i32.add
        local.set $acc
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $loop
      end
    end
    local.get $acc)
  (func $mul_f64 (export "mul_f64") (param $x f64) (param $y f64) (result f64)
    local.get $x
    local.get $y
    f64.mul))
