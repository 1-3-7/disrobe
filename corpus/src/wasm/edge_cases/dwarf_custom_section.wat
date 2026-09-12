(module
  (func $entry (export "entry") (result i32)
    i32.const 42
  )
  (@custom "name" "\01\05entry")
  (@custom "external_debug_info" "\01\10dwarf-hint-blob")
  (@custom ".debug_info" "stub-debug-info-section")
  (@custom ".debug_line" "stub-debug-line-section")
)
