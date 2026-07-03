(module
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    (loop $spin
      br $spin)
    (i32.const 0)))
