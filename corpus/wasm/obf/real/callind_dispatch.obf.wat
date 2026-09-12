(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (table (;0;) 4 4 funcref)
  (memory (;0;) 2)
  (global (;0;) (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "run" (func 0))
  (elem (;0;) (i32.const 1) func 1 2 3)
  (func (;0;) (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 2
    local.get 2
    global.set 0
    local.get 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    i32.const 0
    i32.load offset=65536
    local.set 3
    local.get 2
    local.get 2
    i32.load offset=12
    local.get 2
    i32.load offset=8
    local.get 3
    call_indirect (type 0)
    i32.store offset=4
    i32.const 0
    i32.load offset=65540
    local.set 4
    local.get 2
    local.get 2
    i32.load offset=4
    local.get 2
    i32.load offset=8
    local.get 4
    call_indirect (type 0)
    i32.store
    i32.const 0
    i32.load offset=65544
    local.set 5
    local.get 2
    i32.load
    local.get 2
    i32.load offset=12
    local.get 5
    call_indirect (type 0)
    local.set 6
    local.get 2
    i32.const 16
    i32.add
    global.set 0
    local.get 6
    return
  )
  (func (;1;) (type 0) (param i32 i32) (result i32)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 2
    local.get 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    i32.load offset=12
    local.get 2
    i32.load offset=8
    i32.add
    return
  )
  (func (;2;) (type 0) (param i32 i32) (result i32)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 2
    local.get 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    i32.load offset=12
    local.get 2
    i32.load offset=8
    i32.mul
    return
  )
  (func (;3;) (type 0) (param i32 i32) (result i32)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 2
    local.get 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    i32.load offset=12
    local.get 2
    i32.load offset=8
    i32.sub
    return
  )
  (data (;0;) (i32.const 65536) "\01\00\00\00\02\00\00\00\03\00\00\00")
)
