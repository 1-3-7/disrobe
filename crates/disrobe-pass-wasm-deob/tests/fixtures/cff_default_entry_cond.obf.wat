(module
  (type (func (param i32) (result i32)))
  (memory 1)
  (export "entry_cond" (func 0))
  (func (type 0) (param i32) (result i32)
    (local i32 i32)
    i32.const 0
    local.set 1
    local.get 1
    i32.const 7
    i32.store
    local.get 1
    i32.const 0
    i32.store offset=4
    loop
      local.get 1
      i32.load
      local.set 2
      block
        block
          block
            local.get 2
            br_table 0 1 0
          end
          local.get 1
          local.get 1
          i32.load offset=4
          i32.const 1
          i32.add
          i32.store offset=4
          block
            block
              local.get 1
              i32.load offset=4
              i32.const 2
              i32.lt_u
              br_if 0
              local.get 1
              i32.const 1
              i32.store
              br 1
            end
            local.get 1
            i32.const -1
            i32.store
          end
          br 1
        end
        local.get 1
        i32.load offset=4
        return
      end
      br 0
    end
    unreachable
  )
)
