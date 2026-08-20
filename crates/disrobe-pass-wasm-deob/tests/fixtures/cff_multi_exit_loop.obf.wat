(module
  (type (;0;) (func (param i32) (result i32)))
  (export "reduce_bounded" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    (local i32 i32)
    i32.const 0
    local.set 1
    i32.const 0
    local.set 2
    loop $dispatch (result i32)
      block $latch
        block $case4
          block $case3
            block $case2
              block $case1
                block $case0
                  local.get 2
                  br_table $case0 $case1 $case2 $case3 $case4
                end
                block $s0_join
                  block $s0_else
                    local.get 0
                    i32.const 0
                    i32.gt_s
                    i32.eqz
                    br_if $s0_else
                    i32.const 1
                    local.set 2
                    br $s0_join
                  end
                  i32.const 3
                  local.set 2
                end
                br $latch
              end
              block $s1_join
                block $s1_else
                  local.get 1
                  i32.const 50
                  i32.gt_s
                  i32.eqz
                  br_if $s1_else
                  i32.const 4
                  local.set 2
                  br $s1_join
                end
                i32.const 2
                local.set 2
              end
              br $latch
            end
            local.get 1
            local.get 0
            i32.add
            local.set 1
            local.get 0
            i32.const 1
            i32.sub
            local.set 0
            i32.const 0
            local.set 2
            br $latch
          end
          local.get 1
          i32.const 100
          i32.add
          return
        end
        local.get 1
        i32.const 2
        i32.mul
        return
      end
      br $dispatch
    end
  )
)
