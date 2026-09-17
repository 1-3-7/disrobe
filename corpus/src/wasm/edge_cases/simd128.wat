(module
  (memory 1)
  (func $add_vec (export "add_vec") (param $a v128) (param $b v128) (result v128)
    local.get $a
    local.get $b
    i32x4.add
  )
  (func $mul_vec (export "mul_vec") (param $a v128) (param $b v128) (result v128)
    local.get $a
    local.get $b
    f32x4.mul
  )
  (func $splat (export "splat") (param $v i32) (result v128)
    local.get $v
    i32x4.splat
  )
  (func $shuffle (export "shuffle") (param $a v128) (param $b v128) (result v128)
    local.get $a
    local.get $b
    i8x16.shuffle 0 16 1 17 2 18 3 19 4 20 5 21 6 22 7 23
  )
  (func $load_lane (export "load_lane") (param $addr i32) (param $base v128) (result v128)
    local.get $addr
    local.get $base
    v128.load32_lane 0
  )
  (func $relaxed_madd (export "relaxed_madd") (param $a v128) (param $b v128) (param $c v128) (result v128)
    local.get $a
    local.get $b
    local.get $c
    f32x4.relaxed_madd
  )
)
