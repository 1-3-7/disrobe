(module
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    (local $page i32)
    (loop $grow
      (local.set $page (memory.grow (i32.const 1)))
      (br_if $grow (i32.ne (local.get $page) (i32.const -1))))
    (unreachable)))
