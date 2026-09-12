(module
  (table $funcs 4 funcref)
  (table $refs 4 externref)
  (func $callee (param i32) (result i32)
    local.get 0
    i32.const 7
    i32.mul
  )
  (elem (table $funcs) (i32.const 0) func $callee)

  (func $set_ext (export "set_ext") (param $i i32) (param $r externref)
    local.get $i
    local.get $r
    table.set $refs
  )

  (func $get_ext (export "get_ext") (param $i i32) (result externref)
    local.get $i
    table.get $refs
  )

  (func $is_null_ext (export "is_null_ext") (param $r externref) (result i32)
    local.get $r
    ref.is_null
  )

  (func $invoke (export "invoke") (param $i i32) (param $arg i32) (result i32)
    local.get $arg
    local.get $i
    call_indirect $funcs (param i32) (result i32)
  )
)
