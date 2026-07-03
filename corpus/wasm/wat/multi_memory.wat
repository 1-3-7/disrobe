(module
  (memory $m0 1 4)
  (memory $m1 1 4)
  (data (memory $m1) (i32.const 0) "abcd")
  (func (export "cross_load_store") (param i32) (result i32)
    local.get 0
    i32.load $m1 offset=4 align=4
    local.get 0
    i32.load $m0 offset=8 align=2
    i32.add
    local.get 0
    i32.const 7
    i32.store $m1 offset=12 align=4
    return)
  (func (export "sizes") (result i32)
    memory.size $m1
    memory.size $m0
    i32.add)
  (func (export "grow_second") (param i32) (result i32)
    local.get 0
    memory.grow $m1)
  (func (export "bulk") (param i32) (param i32) (param i32)
    local.get 0
    local.get 1
    local.get 2
    memory.copy $m1 $m0
    local.get 0
    local.get 1
    local.get 2
    memory.fill $m1
    local.get 0
    local.get 1
    local.get 2
    memory.init $m1 0
    data.drop 0))
