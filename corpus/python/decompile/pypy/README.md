PyPy decompile fixtures.

These are SOURCE files (not compiled .pyc). The corresponding tests in
`crates/disrobe-pass-py-decompile/tests/pypy_compat.rs` synthesize the
PyPy bytecode by hand because the pypy3 toolchain is not reliably
available in CI.

Each file documents the surface-language shape that the decompiler must
emit when it sees the matching PyPy private opcode pattern.

| fixture | exercises |
|---|---|
| synthetic_lookup_call_method.py | LOOKUP_METHOD + CALL_METHOD pair |
| synthetic_build_list_from_arg.py | BUILD_LIST_FROM_ARG |
| synthetic_jump_if_not_debug.py | JUMP_IF_NOT_DEBUG assertion-skip |
