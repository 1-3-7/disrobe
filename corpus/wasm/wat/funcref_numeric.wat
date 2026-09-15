(module
  (type $unary (func (param i32) (result i32)))
  (type $binary (func (param i32 i32) (result i32)))

  (func $square (param $x i32) (result i32)
    local.get $x
    local.get $x
    i32.mul)

  (func $negate (param $x i32) (result i32)
    i32.const 0
    local.get $x
    i32.sub)

  (func $adder (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)

  (elem declare func $square $negate $adder)

  (func $apply_square (export "apply_square") (param $x i32) (result i32)
    local.get $x
    ref.func $square
    call_ref $unary)

  (func $apply_negate (export "apply_negate") (param $x i32) (result i32)
    local.get $x
    ref.func $negate
    call_ref $unary)

  (func $apply_binary (export "apply_binary") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    ref.func $adder
    call_ref $binary)

  (func $compose_square_negate (export "compose_square_negate") (param $x i32) (result i32)
    local.get $x
    ref.func $square
    call_ref $unary
    ref.func $negate
    call_ref $unary))
