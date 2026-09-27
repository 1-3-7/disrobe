(module
  (global (mut i32) (i32.const 0))
  (global (export "effect_count") (mut i32) (i32.const 0))
  (func $classify_global (export "classify_global") (param i32) (result i32)
    (local i32 i32)
    i32.const 0
    global.set 0
    loop $dispatch (result i32)
      global.get 0
      local.tee 2
      drop
      call $count_effect
      block $next
        block $state3
          block $state2
            block $state1
              block $state0
                local.get 2
                br_table $state0 $state1 $state2 $state3
              end
              local.get 0
              i32.const 1
              i32.shl
              local.set 1
              block $chosen
                block $otherwise
                  i32.const 7
                  local.get 0
                  i32.lt_s
                  i32.eqz
                  br_if $otherwise
                  i32.const 1
                  global.set 0
                  br $chosen
                end
                i32.const 2
                global.set 0
              end
              br $next
            end
            local.get 1
            i32.const 2
            i32.mul
            local.get 0
            i32.add
            i32.const 30
            i32.sub
            local.set 1
            i32.const 3
            global.set 0
            br $next
          end
          local.get 1
          i32.const 11
          i32.sub
          local.set 1
          i32.const 3
          global.set 0
          br $next
        end
        local.get 1
        return
      end
      br $dispatch
    end
  )
  (func $count_effect
    global.get 1
    i32.const 1
    i32.add
    global.set 1
  )
)
