(module
  (memory i64 1 1 shared)
  (func (export "memory64_overflow_misaligned") (result i32)
    (i32.atomic.load offset=2 align=4
      (i64.const -1))))
