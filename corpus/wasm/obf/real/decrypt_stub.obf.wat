(module
  (type (;0;) (func (result i32)))
  (table (;0;) 1 1 funcref)
  (memory (;0;) 2)
  (global (;0;) (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "plaintext_ptr" (func 0))
  (func (;0;) (type 0) (result i32)
    (local i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 0
    local.get 0
    i32.const 0
    i32.store offset=12
    block ;; label = @1
      loop ;; label = @2
        local.get 0
        i32.load offset=12
        i32.const 10
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 0
        local.get 0
        i32.load offset=12
        i32.load8_u offset=65536
        i32.store8 offset=11
        local.get 0
        i32.load8_u offset=11
        i32.const 255
        i32.and
        i32.const 75
        i32.xor
        local.set 1
        local.get 0
        i32.load offset=12
        local.get 1
        i32.store8 offset=65536
        local.get 0
        local.get 0
        i32.load offset=12
        i32.const 1
        i32.add
        i32.store offset=12
        br 0 (;@2;)
      end
    end
    i32.const 65536
    return
  )
  (data (;0;) (i32.const 65536) "#.''$<$9'/")
)
