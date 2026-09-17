(module
  (type (;0;) (func (param i32) (result i32)))
  (memory (;0;) 1)
  (global (;0;) (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "pipeline" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    local.get 0
    i32.const 5
    i32.mul
    i32.const 15
    i32.add
    i32.const 17
    i32.xor
  )
)
