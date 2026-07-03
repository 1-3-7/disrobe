(module
  (type (;0;) (func (param i32) (result i32)))
  (table (;0;) 1 1 funcref)
  (memory (;0;) 2)
  (global (;0;) (mut i32) i32.const 66560)
  (export "memory" (memory 0))
  (export "classify" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    (local i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    i32.store offset=12
    local.get 1
    i32.const 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    loop (result i32) ;; label = @1
      local.get 1
      i32.load offset=8
      local.set 2
      local.get 2
      i32.const 2
      i32.gt_u
      drop
      block ;; label = @2
        block ;; label = @3
          block ;; label = @4
            block ;; label = @5
              block ;; label = @6
                local.get 2
                br_table 0 (;@6;) 1 (;@5;) 2 (;@4;) 3 (;@3;)
              end
              local.get 1
              local.get 1
              i32.load offset=12
              i32.const 1
              i32.add
              i32.store offset=4
              block ;; label = @6
                block ;; label = @7
                  local.get 1
                  i32.load offset=12
                  i32.const 10
                  i32.gt_s
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if 0 (;@7;)
                  local.get 1
                  i32.const 1
                  i32.store offset=8
                  br 1 (;@6;)
                end
                local.get 1
                i32.const 2
                i32.store offset=8
              end
              br 3 (;@2;)
            end
            local.get 1
            local.get 1
            i32.load offset=4
            i32.const 3
            i32.mul
            i32.store offset=4
            local.get 1
            i32.const 3
            i32.store offset=8
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i32.load offset=4
          i32.const 7
          i32.sub
          i32.store offset=4
          local.get 1
          i32.const 3
          i32.store offset=8
          br 1 (;@2;)
        end
        local.get 1
        i32.load offset=4
        return
      end
      br 0 (;@1;)
    end
  )
)
