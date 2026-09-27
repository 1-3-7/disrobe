(module
  (func $reduce_join (export "reduce_join") (param i32) (result i32)
    (local i32)
    block $done
      loop $again
        local.get 0
        i32.const 0
        i32.le_s
        if
          local.get 1
          i32.const 11
          i32.sub
          local.set 1
          br $done
        end
        local.get 1
        i32.const 60
        i32.gt_s
        if
          local.get 1
          i32.const 7
          i32.mul
          local.set 1
          br $done
        end
        local.get 1
        local.get 0
        i32.add
        i32.const 1
        i32.add
        local.set 1
        local.get 0
        i32.const 3
        i32.sub
        local.set 0
        br $again
      end
    end
    local.get 1
  )
)
