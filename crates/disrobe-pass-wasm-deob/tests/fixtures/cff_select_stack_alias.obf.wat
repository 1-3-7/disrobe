(module
  (memory 1)
  (func $scaled_magnitude (export "scaled_magnitude") (param i32) (result i32)
    (local i32 i32)
    i32.const 24
    local.set 1
    local.get 1
    local.get 0
    i32.const 7
    i32.mul
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    loop $dispatch
      local.get 1
      i32.load offset=4
      local.set 2
      block $next
        block $state2
          block $state1
            block $state0
              local.get 2
              br_table $state0 $state1 $state2 $state2
            end
            local.get 1
            i32.const 2
            i32.const 1
            drop
            drop
            i32.const 1
            i32.const 2
            local.get 0
            i32.const 0
            i32.lt_s
            select
            i32.store offset=4
            br $next
          end
          local.get 1
          i32.const 0
          local.get 1
          i32.load offset=8
          i32.sub
          i32.store offset=8
          local.get 1
          i32.const 2
          i32.store offset=4
          br $next
        end
        local.get 1
        i32.load offset=8
        return
      end
      br $dispatch
    end
    unreachable
  )
)
