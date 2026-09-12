(module
  (memory 1 1 shared)
  (func (export "misaligned") (result i32)
    (i32.atomic.load align=4
      (i32.const 1))))
