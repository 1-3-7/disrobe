(module
  (type $s (shared (struct (field (mut i32)))))
  (type $a (shared (array (mut i32))))
  (global $g (mut i32) (i32.const 0))
  (table $t 4 (ref null func))
  (func (export "gatomic") (param i32) (result i32)
    global.atomic.get seq_cst $g
    drop
    local.get 0
    global.atomic.set seq_cst $g
    local.get 0
    global.atomic.rmw.add seq_cst $g
    drop
    local.get 0
    global.atomic.rmw.xchg seq_cst $g
    drop
    local.get 0
    local.get 0
    global.atomic.rmw.cmpxchg seq_cst $g)

  (func (export "satomic") (param (ref $s) i32) (result i32)
    local.get 0
    struct.atomic.get seq_cst $s 0
    drop
    local.get 0
    local.get 1
    struct.atomic.set seq_cst $s 0
    local.get 0
    local.get 1
    struct.atomic.rmw.add seq_cst $s 0
    drop
    local.get 0
    local.get 1
    struct.atomic.rmw.xchg seq_cst $s 0
    drop
    local.get 0
    local.get 1
    local.get 1
    struct.atomic.rmw.cmpxchg seq_cst $s 0)

  (func (export "aatomic") (param (ref $a) i32) (result i32)
    local.get 0
    local.get 1
    array.atomic.get seq_cst $a
    drop
    local.get 0
    local.get 1
    local.get 1
    array.atomic.set seq_cst $a
    local.get 0
    local.get 1
    local.get 1
    array.atomic.rmw.add seq_cst $a
    drop
    local.get 0
    local.get 1
    local.get 1
    array.atomic.rmw.xchg seq_cst $a
    drop
    local.get 0
    local.get 1
    local.get 1
    local.get 1
    array.atomic.rmw.cmpxchg seq_cst $a)

  (func (export "tatomic") (param i32) (result i32)
    local.get 0
    table.atomic.get seq_cst $t
    drop
    local.get 0
    ref.null func
    table.atomic.set seq_cst $t
    local.get 0
    ref.null func
    table.atomic.rmw.xchg seq_cst $t
    drop
    local.get 0
    ref.null func
    ref.null func
    table.atomic.rmw.cmpxchg seq_cst $t
    drop
    i32.const 0)

  (func (export "i31shared") (param i32) (result i32)
    local.get 0
    ref.i31_shared
    i31.get_s))
