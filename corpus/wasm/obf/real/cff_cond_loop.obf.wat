(module
  (type (;0;) (func (param i32) (result i32)))
  (table (;0;) 1 1 funcref)
  (memory (;0;) 2)
  (global (;0;) (mut i32) i32.const 66560)
  (export "memory" (memory 0))
  (export "accumulate" (func 0))
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
    local.get 1
    i32.const 0
    i32.store
    loop (result i32) ;; label = @1
      local.get 1
      i32.load offset=8
      local.set 2
      local.get 2
      i32.const 5
      i32.gt_u
      drop
      block ;; label = @2
        block ;; label = @3
          block ;; label = @4
            block ;; label = @5
              block ;; label = @6
                block ;; label = @7
                  block ;; label = @8
                    local.get 2
                    br_table 0 (;@8;) 1 (;@7;) 2 (;@6;) 3 (;@5;) 5 (;@3;) 4 (;@4;) 5 (;@3;)
                  end
                  block ;; label = @8
                    block ;; label = @9
                      local.get 1
                      i32.load offset=4
                      local.get 1
                      i32.load offset=12
                      i32.lt_s
                      i32.const 1
                      i32.and
                      i32.eqz
                      br_if 0 (;@9;)
                      local.get 1
                      i32.const 1
                      i32.store offset=8
                      br 1 (;@8;)
                    end
                    local.get 1
                    i32.const 4
                    i32.store offset=8
                  end
                  br 5 (;@2;)
                end
                block ;; label = @7
                  block ;; label = @8
                    local.get 1
                    i32.load offset=4
                    i32.const 1
                    i32.and
                    br_if 0 (;@8;)
                    local.get 1
                    i32.const 2
                    i32.store offset=8
                    br 1 (;@7;)
                  end
                  local.get 1
                  i32.const 3
                  i32.store offset=8
                end
                br 4 (;@2;)
              end
              local.get 1
              local.get 1
              i32.load
              local.get 1
              i32.load offset=4
              i32.const 1
              i32.shl
              i32.add
              i32.store
              local.get 1
              i32.const 5
              i32.store offset=8
              br 3 (;@2;)
            end
            local.get 1
            local.get 1
            i32.load
            local.get 1
            i32.load offset=4
            i32.add
            i32.const 1
            i32.add
            i32.store
            local.get 1
            i32.const 5
            i32.store offset=8
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i32.load offset=4
          i32.const 1
          i32.add
          i32.store offset=4
          local.get 1
          i32.const 0
          i32.store offset=8
          br 1 (;@2;)
        end
        local.get 1
        i32.load
        return
      end
      br 0 (;@1;)
    end
  )
)
