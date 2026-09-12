(module
  (memory i64 1 1 shared)
  (func (export "memory64_uint64_max_offset") (result i32)
    (i32.atomic.load offset=18446744073709551615 align=4
      (i64.const 1))))
