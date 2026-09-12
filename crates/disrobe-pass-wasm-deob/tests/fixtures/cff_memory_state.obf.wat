(module
  (type (;0;) (func (param i32) (result i32)))
  (memory (;0;) 1)
  (export "classify_memory" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    (local i32 i32 i32)
    i32.const 0
    local.set 1
    i32.const 32
    local.set 2
    local.get 2
    i32.const 0
    i32.store offset=4
    loop (result i32) ;; label = @1
      local.get 2
      i32.load offset=4
      local.set 3
      block ;; label = @2
        block ;; label = @3
          block ;; label = @4
            block ;; label = @5
              block ;; label = @6
                local.get 3
                br_table 0 (;@6;) 1 (;@5;) 2 (;@4;) 3 (;@3;)
              end
              local.get 0
              i32.const 1
              i32.add
              local.set 1
              block ;; label = @6
                block ;; label = @7
                  local.get 0
                  i32.const 10
                  i32.gt_s
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if 0 (;@7;)
                  local.get 2
                  i32.const 1
                  i32.store offset=4
                  br 1 (;@6;)
                end
                local.get 2
                i32.const 2
                i32.store offset=4
              end
              br 3 (;@2;)
            end
            local.get 1
            i32.const 3
            i32.mul
            local.set 1
            local.get 2
            i32.const 3
            i32.store offset=4
            br 2 (;@2;)
          end
          local.get 1
          i32.const 7
          i32.sub
          local.set 1
          local.get 2
          i32.const 3
          i32.store offset=4
          br 1 (;@2;)
        end
        local.get 1
        return
      end
      br 0 (;@1;)
    end
  )
)
