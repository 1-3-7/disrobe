(module
  (type $bin (func (param i32 i32) (result i32)))
  (import "env" "op_xor" (func $op_xor (type $bin)))
  (import "env" "op_and" (func $op_and (type $bin)))
  (func $mix (export "mix") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    call $op_xor
    local.get 0
    local.get 1
    call $op_and
    i32.add))
