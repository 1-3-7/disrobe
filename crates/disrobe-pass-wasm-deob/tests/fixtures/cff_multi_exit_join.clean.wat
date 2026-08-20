(module
  (type (;0;) (func (param i32) (result i32)))
  (export "reduce_join" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    (local i32)
    i32.const 0
    local.set 1
    block $done
      loop $top
        local.get 0
        i32.const 0
        i32.le_s
        if
          local.get 1
          i32.const 100
          i32.add
          local.set 1
          br $done
        end
        local.get 1
        i32.const 50
        i32.gt_s
        if
          local.get 1
          i32.const 2
          i32.mul
          local.set 1
          br $done
        end
        local.get 1
        local.get 0
        i32.add
        local.set 1
        local.get 0
        i32.const 1
        i32.sub
        local.set 0
        br $top
      end
    end
    local.get 1
  )
)
