(module
  (type (;0;) (func (param i32) (result i32)))
  (export "scale_then_leave" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    (local i32 i32)
    block $root
      i32.const 0
      local.set 1
      i32.const 0
      local.set 2
      loop $dispatch
        block $latch
          block $case2
            block $case1
              block $case0
                local.get 2
                br_table $case0 $case1 $case2
              end
              local.get 0
              i32.const 2
              i32.mul
              i32.const 1
              i32.add
              local.set 1
              i32.const 1
              local.set 2
              br $latch
            end
            br $root
          end
          i32.const -1
          local.set 1
          i32.const 1
          local.set 2
          br $latch
        end
        br $dispatch
      end
      i32.const 999
      local.set 1
    end
    local.get 1
  )
)
