(module
  (rec
    (type $shape (sub (struct (field $kind i32))))
    (type $circle (sub $shape (struct (field $kind i32) (field $r (mut i32)))))
    (type $rect (sub final $shape (struct (field $kind i32) (field $w i32) (field $h i32)))))

  (type $imm_pair (struct (field i64) (field i64)))
  (type $row (array (mut i32)))
  (type $frozen (array i32))

  (func $circle_radius_or_zero (export "circle_radius_or_zero") (param $r anyref) (result i32)
    (block $is_circle (result (ref $circle))
      local.get $r
      br_on_cast $is_circle anyref (ref $circle)
      drop
      i32.const 0
      return)
    struct.get $circle $r)

  (func $rect_area (export "rect_area") (param $w i32) (param $h i32) (result i32)
    (local $box (ref $rect))
    i32.const 2
    local.get $w
    local.get $h
    struct.new $rect
    local.set $box
    local.get $box
    struct.get $rect $w
    local.get $box
    struct.get $rect $h
    i32.mul)

  (func $is_shape (export "is_shape") (param $r anyref) (result i32)
    local.get $r
    ref.test (ref $shape))

  (func $imm_sum (export "imm_sum") (param $a i64) (param $b i64) (result i64)
    (local $p (ref $imm_pair))
    local.get $a
    local.get $b
    struct.new $imm_pair
    local.set $p
    local.get $p
    struct.get $imm_pair 0
    local.get $p
    struct.get $imm_pair 1
    i64.add)

  (func $row_filled (export "row_filled") (param $len i32) (param $v i32) (param $idx i32) (result i32)
    (local $a (ref $row))
    local.get $v
    local.get $len
    array.new $row
    local.set $a
    local.get $a
    i32.const 0
    local.get $v
    local.get $len
    array.fill $row
    local.get $a
    local.get $idx
    array.get $row)

  (func $row_default_len (export "row_default_len") (param $len i32) (result i32)
    local.get $len
    array.new_default $row
    array.len)

  (func $frozen_at (export "frozen_at") (param $a i32) (param $b i32) (param $idx i32) (result i32)
    (local $arr (ref $frozen))
    local.get $a
    local.get $b
    array.new_fixed $frozen 2
    local.set $arr
    local.get $arr
    local.get $idx
    array.get $frozen)

  (func $i31_box_unbox (export "i31_box_unbox") (param $v i32) (result i32)
    local.get $v
    ref.i31
    i31.get_s))
