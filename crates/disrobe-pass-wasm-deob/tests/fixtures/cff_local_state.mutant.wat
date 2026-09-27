(module
  (func $classify_local (export "classify_local") (param i32) (result i32)
    (local i32 i32)
    i32.const 0
    local.set 2
    local.get 0
    i32.const 3
    i32.sub
    local.set 1
    loop $dispatch (result i32)
      block $next
        block $state3
          block $state2
            block $state1
              block $state0
                local.get 2
                br_table $state0 $state1 $state2 $state3
              end
              block $chosen
                block $otherwise
                  local.get 0
                  i32.const 6
                  i32.le_s
                  br_if $otherwise
                  i32.const 2
                  local.set 2
                  br $chosen
                end
                i32.const 1
                local.set 2
              end
              br $next
            end
            local.get 1
            i32.const 2
            i32.shl
            local.set 1
            i32.const 3
            local.set 2
            br $next
          end
          i32.const 5
          local.get 1
          i32.const 1
          i32.shl
          i32.sub
          local.set 1
          i32.const 3
          local.set 2
          br $next
        end
        local.get 1
        return
      end
      br $dispatch
    end
  )
)
