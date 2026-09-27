(module
  (memory 1)
  (func $classify_memory (export "classify_memory") (param i32) (result i32)
    (local i32 i32 i32)
    i32.const 32
    local.set 2
    local.get 2
    i32.const 0
    i32.store offset=4
    loop $dispatch (result i32)
      local.get 2
      i32.load offset=4
      local.set 3
      block $next
        block $state3
          block $state2
            block $state1
              block $state0
                local.get 3
                br_table $state0 $state1 $state2 $state3
              end
              local.get 0
              i32.const 3
              i32.mul
              local.set 1
              block $chosen
                block $otherwise
                  local.get 0
                  i32.const 8
                  i32.gt_s
                  i32.eqz
                  br_if $otherwise
                  local.get 2
                  i32.const 1
                  i32.store offset=4
                  br $chosen
                end
                local.get 2
                i32.const 2
                i32.store offset=4
              end
              br $next
            end
            local.get 1
            i32.const 7
            i32.add
            local.set 1
            local.get 2
            i32.const 3
            i32.store offset=4
            br $next
          end
          i32.const 4
          local.get 0
          i32.sub
          local.set 1
          local.get 2
          i32.const 3
          i32.store offset=4
          br $next
        end
        local.get 1
        return
      end
      br $dispatch
    end
  )
)
