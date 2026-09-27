(module
  (func $reduce_bounded (export "reduce_bounded") (param i32) (result i32)
    (local i32)
    block $drained
      loop $again
        local.get 0
        i32.const 0
        i32.le_s
        br_if $drained
        local.get 1
        i32.const 40
        i32.gt_s
        if
          local.get 1
          i32.const 5
          i32.mul
          return
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
        br $again
      end
    end
    local.get 1
    i32.const 9
    i32.sub
  )
)
