(module
  (type $bin (func (param i32 i32) (result i32)))
  (table 3 funcref)
  (elem (i32.const 0) $frag_add $frag_mul $frag_sub)
  (func $frag_add (type $bin)
    local.get 0
    local.get 1
    i32.add)
  (func $frag_mul (type $bin)
    local.get 0
    local.get 1
    i32.mul)
  (func $frag_sub (type $bin)
    local.get 0
    local.get 1
    i32.sub)
  (func $run (export "run") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.const 0
    call_indirect (type $bin)
    local.get 1
    i32.const 1
    call_indirect (type $bin)
    local.get 0
    i32.const 2
    call_indirect (type $bin)))
