# Authored Python fixtures

`binary_ops.py`, `simple_const.py`, `slices.py`, `hello.py` and `header_probe.py` are written for this repository. Each is compiled by the pinned CPython of its band with a hash-based header, so a rebuild is byte-identical:

```
python3.X -c "import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)" corpus/python/decompile/authored/<name>.py corpus/python/decompile/authored/compiled/<name>.3.X.pyc
```

| file | interpreter |
|------|-------------|
| `compiled/*.3.11.pyc` | CPython 3.11.15 |
| `compiled/*.3.12.pyc` | CPython 3.12.13 |

`playground/public/samples/hello.pyc` is a copy of `compiled/hello.3.12.pyc`, and `crates/disrobe-wasm/tests/fixtures/sample.pyc` is a copy of `compiled/slices.3.12.pyc`.

`header_probe.py` ends in a comment whose number was searched for so that the first 16 bytes of `compiled/header_probe.3.12.pyc` (magic, flags and source hash) decrypt to the gzip prefix `1f 8b` under the D-Link DAP-1720 Alpha v1 key, and the string literal is sized so the file is a whole number of 16-byte blocks. `crates/disrobe-binfmt/tests/firmware_vendor.rs` uses it to check that the firmware detector does not claim CPython bytecode on that two-byte coincidence.
