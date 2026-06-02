(module
  (memory $m 1 16 shared)
  (func $atomic_add (export "atomic_add") (param $addr i32) (param $delta i32) (result i32)
    local.get $addr
    local.get $delta
    i32.atomic.rmw.add
  )
  (func $atomic_cas (export "atomic_cas") (param $addr i32) (param $expected i32) (param $replacement i32) (result i32)
    local.get $addr
    local.get $expected
    local.get $replacement
    i32.atomic.rmw.cmpxchg
  )
  (func $atomic_load (export "atomic_load") (param $addr i32) (result i32)
    local.get $addr
    i32.atomic.load
  )
  (func $atomic_wait (export "atomic_wait") (param $addr i32) (param $expected i32) (param $timeout i64) (result i32)
    local.get $addr
    local.get $expected
    local.get $timeout
    memory.atomic.wait32
  )
  (func $atomic_notify (export "atomic_notify") (param $addr i32) (param $count i32) (result i32)
    local.get $addr
    local.get $count
    memory.atomic.notify
  )
)
