(module
  (table $t 2 16 funcref)
  (func $a (result i32) i32.const 100)
  (func $b (result i32) i32.const 200)
  (elem (table $t) (i32.const 0) func $a $b)

  (func $grow (export "grow") (param $extra i32) (param $init funcref) (result i32)
    local.get $init
    local.get $extra
    table.grow $t
  )
  (func $fill (export "fill") (param $offset i32) (param $count i32) (param $value funcref)
    local.get $offset
    local.get $value
    local.get $count
    table.fill $t
  )
  (func $copy_block (export "copy_block") (param $dst i32) (param $src i32) (param $len i32)
    local.get $dst
    local.get $src
    local.get $len
    table.copy $t $t
  )
  (func $size (export "size") (result i32)
    table.size $t
  )
)
