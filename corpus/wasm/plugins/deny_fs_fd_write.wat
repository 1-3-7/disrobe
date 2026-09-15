(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open
      (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    (drop (call $fd_write
      (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0)))
    (i32.const 0)))
