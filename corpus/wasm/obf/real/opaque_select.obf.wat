(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func (param i32) (result i32)))
  (memory (;0;) 1)
  (global (;0;) (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "pick" (func 0))
  (export "scale" (func 2))
  (func (;0;) (type 0) (param i32 i32) (result i32)
    (local i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 2
    local.get 2
    global.set 0
    local.get 2
    local.get 0
    i32.store offset=8
    local.get 2
    local.get 1
    i32.store offset=4
    block ;; label = @1
      block ;; label = @2
        i32.const 9
        call 1
        i32.const 1
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        local.get 2
        i32.load offset=8
        local.get 2
        i32.load offset=4
        i32.add
        i32.const 7
        i32.mul
        i32.store offset=12
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.load offset=8
      local.get 2
      i32.load offset=4
      i32.sub
      i32.const 13
      i32.mul
      i32.const 999
      i32.add
      i32.store offset=12
    end
    local.get 2
    i32.load offset=12
    local.set 3
    local.get 2
    i32.const 16
    i32.add
    global.set 0
    local.get 3
    return
  )
  (func (;1;) (type 1) (param i32) (result i32)
    (local i32 i32 i32 i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    i32.store offset=12
    local.get 1
    local.get 1
    i32.load offset=12
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    loop ;; label = @1
      local.get 1
      i32.load offset=8
      i32.const 1
      i32.ne
      local.set 2
      i32.const 0
      local.set 3
      local.get 2
      i32.const 1
      i32.and
      local.set 4
      local.get 3
      local.set 5
      block ;; label = @2
        local.get 4
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=4
        i32.const 1000
        i32.lt_s
        local.set 5
      end
      block ;; label = @2
        local.get 5
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        block ;; label = @3
          block ;; label = @4
            local.get 1
            i32.load offset=8
            i32.const 1
            i32.and
            br_if 0 (;@4;)
            local.get 1
            local.get 1
            i32.load offset=8
            i32.const 2
            i32.div_s
            i32.store offset=8
            br 1 (;@3;)
          end
          local.get 1
          local.get 1
          i32.load offset=8
          i32.const 3
          i32.mul
          i32.const 1
          i32.add
          i32.store offset=8
        end
        local.get 1
        local.get 1
        i32.load offset=4
        i32.const 1
        i32.add
        i32.store offset=4
        br 1 (;@1;)
      end
    end
    local.get 1
    i32.load offset=8
    return
  )
  (func (;2;) (type 1) (param i32) (result i32)
    (local i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    global.set 0
    local.get 1
    local.get 0
    i32.store offset=8
    block ;; label = @1
      block ;; label = @2
        i32.const 27
        call 1
        i32.const 1
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        local.get 1
        i32.load offset=8
        i32.const 3
        i32.mul
        i32.const 11
        i32.add
        i32.store offset=12
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=8
      i32.const 31
      i32.mul
      i32.const 7
      i32.sub
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 2
    local.get 1
    i32.const 16
    i32.add
    global.set 0
    local.get 2
    return
  )
)
