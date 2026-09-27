(module
  (table 1 1 funcref)
  (memory 2)
  (global (mut i32) (i32.const 66560))
  (export "memory" (memory 0))
  (func $classify (export "classify") (param i32) (result i32)
    (local i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    i32.store offset=12
    local.get 1
    i32.const 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    loop $dispatch (result i32)
      local.get 1
      i32.load offset=8
      local.set 2
      local.get 2
      i32.const 2
      i32.gt_u
      drop
      block $next
        block $default
          block $state2
            block $state1
              block $state0
                local.get 2
                br_table $state0 $state1 $state2 $default
              end
              local.get 1
              local.get 1
              i32.load offset=12
              i32.const 2
              i32.add
              i32.store offset=4
              block $chosen
                block $otherwise
                  local.get 1
                  i32.load offset=12
                  i32.const 4
                  i32.gt_s
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if $otherwise
                  local.get 1
                  i32.const 1
                  i32.store offset=8
                  br $chosen
                end
                local.get 1
                i32.const 2
                i32.store offset=8
              end
              br $next
            end
            local.get 1
            local.get 1
            i32.load offset=4
            i32.const 5
            i32.mul
            i32.store offset=4
            local.get 1
            i32.const 9
            i32.store offset=8
            br $next
          end
          local.get 1
          local.get 1
          i32.load offset=4
          i32.const 3
          i32.sub
          i32.store offset=4
          local.get 1
          i32.const -1
          i32.store offset=8
          br $next
        end
        local.get 1
        i32.load offset=4
        return
      end
      br $dispatch
    end
  )
)
