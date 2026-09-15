(module
  (memory i64 1 1 shared)
  (func (export "memory64_aligned_offset_2pow53") (result i32)
    (i32.atomic.load offset=9007199254740992 align=4
      (i64.const 0))))
