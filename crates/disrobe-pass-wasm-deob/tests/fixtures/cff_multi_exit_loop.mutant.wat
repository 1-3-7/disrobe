(module
  (func $reduce_bounded (export "reduce_bounded") (param i32) (result i32)
    (local i32 i32)
    i32.const 0
    local.set 1
    i32.const 0
    local.set 2
    loop $dispatch (result i32)
      block $next
        block $state4
          block $state3
            block $state2
              block $state1
                block $state0
                  local.get 2
                  br_table $state0 $state1 $state2 $state3 $state4
                end
                block $chosen0
                  block $otherwise0
                    local.get 0
                    i32.const 0
                    i32.gt_s
                    i32.eqz
                    br_if $otherwise0
                    i32.const 1
                    local.set 2
                    br $chosen0
                  end
                  i32.const 3
                  local.set 2
                end
                br $next
              end
              block $chosen1
                block $otherwise1
                  local.get 1
                  i32.const 40
                  i32.gt_s
                  i32.eqz
                  br_if $otherwise1
                  i32.const 2
                  local.set 2
                  br $chosen1
                end
                i32.const 4
                local.set 2
              end
              br $next
            end
            local.get 1
            local.get 0
            i32.add
            i32.const 3
            i32.add
            local.set 1
            local.get 0
            i32.const 2
            i32.sub
            local.set 0
            i32.const 0
            local.set 2
            br $next
          end
          local.get 1
          i32.const 9
          i32.sub
          return
        end
        local.get 1
        i32.const 5
        i32.mul
        return
      end
      br $dispatch
    end
  )
)
