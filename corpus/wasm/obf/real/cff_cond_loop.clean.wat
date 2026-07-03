(module
  (type (;0;) (func (param i32) (result i32)))
  (table (;0;) 1 1 funcref)
  (memory (;0;) 2)
  (global (;0;) (mut i32) i32.const 66560)
  (export "memory" (memory 0))
  (export "accumulate" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    (local i32 i32 i32 i32 i32)
    block ;; label = @1
      local.get 0
      i32.const 1
      i32.ge_s
      br_if 0 (;@1;)
      i32.const 0
      return
    end
    local.get 0
    i32.const 3
    i32.and
    local.set 1
    block ;; label = @1
      block ;; label = @2
        local.get 0
        i32.const 4
        i32.ge_u
        br_if 0 (;@2;)
        i32.const 0
        local.set 0
        i32.const 0
        local.set 2
        br 1 (;@1;)
      end
      local.get 0
      i32.const 2147483644
      i32.and
      local.set 3
      i32.const 0
      local.set 4
      i32.const 4
      local.set 5
      i32.const 0
      local.set 2
      loop ;; label = @2
        local.get 5
        local.get 2
        i32.add
        local.get 4
        i32.add
        local.get 5
        i32.add
        local.get 4
        i32.const 4
        i32.add
        local.tee 0
        i32.add
        i32.const -2
        i32.add
        local.set 2
        local.get 5
        i32.const 8
        i32.add
        local.set 5
        local.get 0
        local.set 4
        local.get 3
        local.get 0
        i32.ne
        br_if 0 (;@2;)
      end
    end
    block ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.const 1
      i32.shl
      local.set 5
      loop ;; label = @2
        local.get 0
        i32.const 1
        i32.and
        local.set 4
        local.get 0
        i32.const 1
        i32.add
        local.tee 0
        local.get 5
        local.get 4
        select
        local.get 2
        i32.add
        local.set 2
        local.get 5
        i32.const 2
        i32.add
        local.set 5
        local.get 1
        i32.const -1
        i32.add
        local.tee 1
        br_if 0 (;@2;)
      end
    end
    local.get 2
  )
)
