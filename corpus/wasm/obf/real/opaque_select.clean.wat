(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func (param i32) (result i32)))
  (memory (;0;) 1)
  (global (;0;) (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "pick" (func 0))
  (export "scale" (func 1))
  (func (;0;) (type 0) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.add
    i32.const 7
    i32.mul
  )
  (func (;1;) (type 1) (param i32) (result i32)
    local.get 0
    i32.const 3
    i32.mul
    i32.const 11
    i32.add
  )
)
