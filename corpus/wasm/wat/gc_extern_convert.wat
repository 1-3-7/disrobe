(module
  (func (export "round_trip") (param externref) (result externref)
    local.get 0
    any.convert_extern
    extern.convert_any))
