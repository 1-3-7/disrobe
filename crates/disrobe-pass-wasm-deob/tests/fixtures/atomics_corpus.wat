(module
  (memory 1 1 shared)
  (func (export "at") (param i32 i32) (result i32)
    local.get 0
    i32.atomic.load
    drop
    local.get 0
    i32.atomic.load8_u
    drop
    local.get 0
    local.get 1
    i32.atomic.store
    local.get 0
    local.get 1
    i32.atomic.rmw.add
    drop
    local.get 0
    local.get 1
    i32.atomic.rmw.xchg
    drop
    local.get 0
    local.get 1
    local.get 1
    i32.atomic.rmw.cmpxchg
    drop
    local.get 0
    i64.atomic.load
    drop
    local.get 0
    local.get 1
    local.get 1
    memory.atomic.wait32
    drop
    local.get 0
    local.get 1
    memory.atomic.notify
    drop
    atomic.fence
    i32.const 0))
