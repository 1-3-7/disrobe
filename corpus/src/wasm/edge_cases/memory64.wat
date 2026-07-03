(module
  (memory $m i64 1 16)
  (data (memory $m) (i64.const 0) "memory64-edge-case")
  (func $read (export "read") (param $offset i64) (result i32)
    local.get $offset
    i32.load8_u
  )
  (func $write (export "write") (param $offset i64) (param $value i32)
    local.get $offset
    local.get $value
    i32.store8
  )
  (func $size (export "size") (result i64)
    memory.size
  )
)
