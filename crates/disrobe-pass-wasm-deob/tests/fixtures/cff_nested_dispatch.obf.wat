(module
  (func $nested_dispatch (export "nested_dispatch") (param i32) (result i32)
    (local i32 i32 i32)
    i32.const 0
    local.set 1
    i32.const 0
    local.set 2
    loop $dispatch (result i32)
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
              i32.add
              local.set 1
              block $inner_done
                i32.const 0
                local.set 3
                loop $inner_dispatch
                  block $inner_next
                    block $inner3
                      block $inner2
                        block $inner1
                          block $inner0
                            local.get 3
                            br_table $inner0 $inner1 $inner2 $inner3
                          end
                          local.get 1
                          i32.const 5
                          i32.mul
                          local.set 1
                          i32.const 1
                          local.set 3
                          br $inner_next
                        end
                        local.get 1
                        i32.const 4
                        i32.sub
                        local.set 1
                        i32.const 3
                        local.set 3
                        br $inner_next
                      end
                      local.get 1
                      i32.const 9
                      i32.add
                      local.set 1
                      i32.const 3
                      local.set 3
                      br $inner_next
                    end
                    br $inner_done
                  end
                  br $inner_dispatch
                end
              end
              block $chosen
                block $otherwise
                  local.get 0
                  i32.const 7
                  i32.gt_s
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if $otherwise
                  i32.const 1
                  local.set 2
                  br $chosen
                end
                i32.const 2
                local.set 2
              end
              br $next
            end
            local.get 1
            i32.const 100
            i32.add
            local.set 1
            i32.const 3
            local.set 2
            br $next
          end
          local.get 1
          i32.const 2
          i32.mul
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
