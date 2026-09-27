(module
  (memory 1)
  (func $entry_cond (export "entry_cond") (param i32) (result i32)
    (local i32 i32)
    i32.const 0
    local.set 1
    local.get 1
    i32.const 6
    i32.store
    local.get 1
    i32.const 0
    i32.store offset=4
    loop $dispatch
      local.get 1
      i32.load
      local.set 2
      block $next
        block $state1
          block $state0
            local.get 2
            br_table $state0 $state1 $state0
          end
          local.get 1
          local.get 1
          i32.load offset=4
          i32.const 1
          i32.add
          i32.store offset=4
          block $chosen
            block $otherwise
              local.get 1
              i32.load offset=4
              i32.const 4
              i32.lt_u
              br_if $otherwise
              local.get 1
              i32.const 1
              i32.store
              br $chosen
            end
            local.get 1
            i32.const -3
            i32.store
          end
          br $next
        end
        local.get 1
        i32.load offset=4
        return
      end
      br $dispatch
    end
    unreachable
  )
)
