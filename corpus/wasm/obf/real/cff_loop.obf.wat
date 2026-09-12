(module
  (type (func (param i32) (result i32)))
  (memory 1)
  (global (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "loop_sum" (func 0))
  (func (type 0) (param i32) (result i32)
    (local i32 i32 i32)
    i32.const 0
    local.set 1
    local.get 0
    local.set 2
    i32.const 0
    local.set 3
    block
      loop
        block
          block
            local.get 3
            br_table 0 1 3 0
          end
          local.get 2
          i32.const 0
          i32.le_s
          if
            local.get 1
            return
          end
          i32.const 1
          local.set 3
          br 1
        end
        local.get 1
        i32.const 2
        i32.add
        local.set 1
        local.get 2
        i32.const 1
        i32.sub
        local.set 2
        i32.const 0
        local.set 3
        br 0
      end
    end
    local.get 1
  )
)
