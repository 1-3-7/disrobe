(module
  (type (;0;) (func (param i32) (result i32)))
  (type (;1;) (func))
  (global (;0;) (mut i32) (i32.const 0))
  (global (;1;) (mut i32) (i32.const 0))
  (export "classify_global" (func 0))
  (export "effect_count" (global 1))
  (func (;0;) (type 0) (param i32) (result i32)
    (local i32 i32)
    i32.const 0
    local.set 1
    i32.const 0
    global.set 0
    loop (result i32) ;; label = @1
      global.get 0
      local.tee 2
      drop
      call 1
      block ;; label = @2
        block ;; label = @3
          block ;; label = @4
            block ;; label = @5
              block ;; label = @6
                local.get 2
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
                  i32.const 1
                  global.set 0
                  br 1 (;@6;)
                end
                i32.const 2
                global.set 0
              end
              br 3 (;@2;)
            end
            local.get 1
            i32.const 3
            i32.mul
            local.set 1
            i32.const 3
            global.set 0
            br 2 (;@2;)
          end
          local.get 1
          i32.const 7
          i32.sub
          local.set 1
          i32.const 3
          global.set 0
          br 1 (;@2;)
        end
        local.get 1
        return
      end
      br 0 (;@1;)
    end)
  (func (;1;) (type 1)
    global.get 1
    i32.const 1
    i32.add
    global.set 1)
)
