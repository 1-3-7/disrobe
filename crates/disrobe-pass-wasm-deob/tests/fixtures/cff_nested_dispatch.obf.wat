(module
  (func (export "nested_dispatch") (param i32) (result i32)
    (local i32 i32 i32)
    i32.const 0
    local.set 1
    i32.const 0
    local.set 2
    loop (result i32)
      block
        block
          block
            block
              block
                local.get 2
                br_table 0 1 2 3
              end
              local.get 0
              i32.const 1
              i32.add
              local.set 1
              block $inner_exit
                i32.const 0
                local.set 3
                loop $inner_loop
                  block $inner_default
                    block $inner_case3
                      block $inner_case2
                        block $inner_case1
                          block $inner_case0
                            local.get 3
                            br_table $inner_case0 $inner_case1 $inner_case2 $inner_case3
                          end
                          local.get 1
                          i32.const 2
                          i32.mul
                          local.set 1
                          i32.const 1
                          local.set 3
                          br $inner_default
                        end
                        local.get 1
                        i32.const 3
                        i32.add
                        local.set 1
                        i32.const 3
                        local.set 3
                        br $inner_default
                      end
                      local.get 1
                      i32.const 0
                      i32.add
                      local.set 1
                      i32.const 3
                      local.set 3
                      br $inner_default
                    end
                    br $inner_exit
                  end
                  br $inner_loop
                end
              end
              block
                block
                  local.get 0
                  i32.const 10
                  i32.gt_s
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if 0
                  i32.const 1
                  local.set 2
                  br 1
                end
                i32.const 2
                local.set 2
              end
              br 3
            end
            local.get 1
            i32.const 3
            i32.mul
            local.set 1
            i32.const 3
            local.set 2
            br 2
          end
          local.get 1
          i32.const 7
          i32.sub
          local.set 1
          i32.const 3
          local.set 2
          br 1
        end
        local.get 1
        return
      end
      br 0
    end
  )
)
