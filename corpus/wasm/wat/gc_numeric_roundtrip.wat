(module
  (type $pt (struct (field $x (mut i32)) (field $y (mut i32))))
  (type $vec3 (struct (field $a i64) (field $b i64) (field $c i64)))
  (type $row (array (mut i32)))
  (type $longs (array (mut i64)))

  (func $point_dot (export "point_dot")
        (param $x0 i32) (param $y0 i32) (param $x1 i32) (param $y1 i32) (result i32)
    (local $p (ref $pt))
    (local $q (ref $pt))
    local.get $x0
    local.get $y0
    struct.new $pt
    local.set $p
    local.get $x1
    local.get $y1
    struct.new $pt
    local.set $q
    local.get $p
    struct.get $pt $x
    local.get $q
    struct.get $pt $x
    i32.mul
    local.get $p
    struct.get $pt $y
    local.get $q
    struct.get $pt $y
    i32.mul
    i32.add)

  (func $point_translate (export "point_translate")
        (param $x i32) (param $y i32) (param $dx i32) (param $dy i32) (result i32)
    (local $p (ref $pt))
    local.get $x
    local.get $y
    struct.new $pt
    local.set $p
    local.get $p
    local.get $p
    struct.get $pt $x
    local.get $dx
    i32.add
    struct.set $pt $x
    local.get $p
    local.get $p
    struct.get $pt $y
    local.get $dy
    i32.add
    struct.set $pt $y
    local.get $p
    struct.get $pt $x
    local.get $p
    struct.get $pt $y
    i32.add)

  (func $vec3_sum (export "vec3_sum") (param $a i64) (param $b i64) (param $c i64) (result i64)
    (local $v (ref $vec3))
    local.get $a
    local.get $b
    local.get $c
    struct.new $vec3
    local.set $v
    local.get $v
    struct.get $vec3 $a
    local.get $v
    struct.get $vec3 $b
    i64.add
    local.get $v
    struct.get $vec3 $c
    i64.add)

  (func $row_fill_get (export "row_fill_get")
        (param $init i32) (param $len i32) (param $idx i32) (result i32)
    (local $a (ref $row))
    local.get $init
    local.get $len
    array.new $row
    local.set $a
    local.get $a
    local.get $idx
    array.get $row)

  (func $row_set_get (export "row_set_get")
        (param $len i32) (param $idx i32) (param $val i32) (result i32)
    (local $a (ref $row))
    i32.const 0
    local.get $len
    array.new $row
    local.set $a
    local.get $a
    local.get $idx
    local.get $val
    array.set $row
    local.get $a
    local.get $idx
    array.get $row)

  (func $row_length (export "row_length") (param $init i32) (param $len i32) (result i32)
    local.get $init
    local.get $len
    array.new $row
    array.len)

  (func $longs_at (export "longs_at") (param $init i64) (param $len i32) (param $idx i32) (result i64)
    (local $a (ref $longs))
    local.get $init
    local.get $len
    array.new $longs
    local.set $a
    local.get $a
    local.get $idx
    array.get $longs)

  (func $row_fixed_sum (export "row_fixed_sum") (param $a i32) (param $b i32) (param $c i32) (result i32)
    (local $arr (ref $row))
    local.get $a
    local.get $b
    local.get $c
    array.new_fixed $row 3
    local.set $arr
    local.get $arr
    i32.const 0
    array.get $row
    local.get $arr
    i32.const 1
    array.get $row
    i32.add
    local.get $arr
    i32.const 2
    array.get $row
    i32.add)

  (func $i31_signed (export "i31_signed") (param $v i32) (result i32)
    local.get $v
    ref.i31
    i31.get_s)

  (func $i31_unsigned (export "i31_unsigned") (param $v i32) (result i32)
    local.get $v
    ref.i31
    i31.get_u)

  (func $ref_eq_self (export "ref_eq_self") (param $x i32) (param $y i32) (result i32)
    (local $p (ref $pt))
    local.get $x
    local.get $y
    struct.new $pt
    local.set $p
    local.get $p
    ref.is_null))
