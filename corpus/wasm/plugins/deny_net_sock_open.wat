(module
  (import "wasi_snapshot_preview1" "sock_open"
    (func $sock_open (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    (drop (call $sock_open (i32.const 0) (i32.const 0) (i32.const 0)))
    (i32.const 0)))
