(module
  (func $scale_then_leave (export "scale_then_leave") (param i32) (result i32)
    (local i32 i32)
    block $root
      i32.const 0
      local.set 1
      i32.const 0
      local.set 2
      loop $dispatch
        block $next
          block $state2
            block $state1
              block $state0
                local.get 2
                br_table $state0 $state1 $state2
              end
              local.get 0
              i32.const 3
              i32.mul
              i32.const 5
              i32.sub
              local.set 1
              i32.const 1
              local.set 2
              br $next
            end
            br $root
          end
          i32.const 77
          local.set 1
          i32.const 1
          local.set 2
          br $next
        end
        br $dispatch
      end
      i32.const 555
      local.set 1
    end
    local.get 1
  )
)
