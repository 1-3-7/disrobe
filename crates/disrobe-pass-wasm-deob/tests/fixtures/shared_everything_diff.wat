(module
  (global $g (mut i32) (i32.const 0))
  (table $t 0 4096 funcref)

  (func (export "s_tbl_grow") (param i32 i32) (result i32)
    (table.grow $t (ref.null func) (i32.and (local.get 0) (i32.const 3))))

  (func (export "s_global_set_get") (param i32 i32) (result i32)
    (global.atomic.set seq_cst $g (local.get 1))
    (global.atomic.get seq_cst $g))

  (func (export "s_global_rmw_add") (param i32 i32) (result i32)
    (global.atomic.rmw.add seq_cst $g (local.get 1)))

  (func (export "s_global_rmw_sub") (param i32 i32) (result i32)
    (global.atomic.rmw.sub seq_cst $g (local.get 1)))

  (func (export "s_global_rmw_and") (param i32 i32) (result i32)
    (global.atomic.rmw.and seq_cst $g (local.get 1)))

  (func (export "s_global_rmw_or") (param i32 i32) (result i32)
    (global.atomic.rmw.or seq_cst $g (local.get 1)))

  (func (export "s_global_rmw_xor") (param i32 i32) (result i32)
    (global.atomic.rmw.xor seq_cst $g (local.get 1)))

  (func (export "s_global_rmw_xchg") (param i32 i32) (result i32)
    (global.atomic.rmw.xchg seq_cst $g (local.get 1)))

  (func (export "s_global_cmpxchg") (param i32 i32) (result i32)
    (global.atomic.rmw.cmpxchg seq_cst $g (local.get 0) (local.get 1)))

  (func (export "s_global_after_rmw") (param i32 i32) (result i32)
    (global.atomic.get seq_cst $g))

  (func (export "s_tbl_atomic_set_get") (param i32 i32) (result i32)
    (table.atomic.set seq_cst $t
      (i32.and (local.get 0) (i32.const 15))
      (ref.null func))
    (ref.is_null
      (table.atomic.get seq_cst $t (i32.and (local.get 0) (i32.const 15)))))

  (func (export "s_tbl_atomic_xchg") (param i32 i32) (result i32)
    (ref.is_null
      (table.atomic.rmw.xchg seq_cst $t
        (i32.and (local.get 0) (i32.const 15))
        (ref.null func))))

  (func (export "s_tbl_atomic_cmpxchg") (param i32 i32) (result i32)
    (ref.is_null
      (table.atomic.rmw.cmpxchg seq_cst $t
        (i32.and (local.get 0) (i32.const 15))
        (ref.null func)
        (ref.null func))))

  (func (export "s_i31_shared_s") (param i32 i32) (result i32)
    (i31.get_s (ref.i31_shared (local.get 0))))

  (func (export "s_i31_shared_u") (param i32 i32) (result i32)
    (i31.get_u (ref.i31_shared (local.get 0))))

  (func (export "s_fence") (param i32 i32) (result i32)
    (atomic.fence)
    (global.atomic.get seq_cst $g)))
