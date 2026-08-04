(module
  (memory i64 1 1 shared)
  (func (export "effective_address_overflow") (result i32)
    (i32.atomic.load offset=1 align=4
      (i64.const -1))))
