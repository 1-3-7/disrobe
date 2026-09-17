(module
  (type (;0;) (func (param i32) (result i32)))
  (memory (;0;) 1)
  (global (;0;) (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "pipeline" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    (local i32)
    i32.const 0
    local.set 1
    block ;; label = @1
      loop ;; label = @2
        block ;; label = @3
          block ;; label = @4
            block ;; label = @5
              local.get 1
              br_table 0 (;@5;) 1 (;@4;) 2 (;@3;) 4 (;@1;) 0 (;@5;)
            end
            local.get 0
            i32.const 3
            i32.add
            local.set 0
            i32.const 1
            local.set 1
            br 2 (;@2;)
          end
          local.get 0
          i32.const 5
          i32.mul
          local.set 0
          i32.const 2
          local.set 1
          br 1 (;@2;)
        end
        local.get 0
        i32.const 17
        i32.xor
        local.set 0
        i32.const 3
        local.set 1
        br 0 (;@2;)
      end
    end
    local.get 0
  )
)
